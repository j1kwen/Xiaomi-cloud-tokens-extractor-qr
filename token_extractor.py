import argparse
import base64
import hashlib
import json
import logging
import os
import random
import sys
import time
import qrcode
import cv2
import numpy as np

import requests
from colorama import Fore, Style, init

try:
    from Crypto.Cipher import ARC4
except ModuleNotFoundError:
    from Cryptodome.Cipher import ARC4


SERVERS = ["cn", "de", "us", "ru", "tw", "sg", "in", "i2"]
NAME_TO_LEVEL = {
    "CRITICAL": logging.CRITICAL,
    "FATAL": logging.FATAL,
    "ERROR": logging.ERROR,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "NOTSET": logging.NOTSET,
}

parser = argparse.ArgumentParser()
parser.add_argument("-ni", "--non_interactive", required=False, help="Non-nteractive mode", action="store_true")
parser.add_argument("-s", "--server", required=False, help="Server", choices=[*SERVERS, ""])
parser.add_argument("-l", "--log_level", required=False, help="Log level", default="CRITICAL", choices=list(NAME_TO_LEVEL.keys()))
parser.add_argument("-o", "--output", required=False, help="Output file")
args = parser.parse_args()

init(autoreset=True)

class ColorFormatter(logging.Formatter):
    COLORS = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "FATAL": Fore.RED + Style.BRIGHT,
        "ERROR": Fore.RED,
        "WARN": Fore.YELLOW,
        "WARNING": Fore.YELLOW,
        "INFO": Fore.GREEN,
        "DEBUG": Fore.BLUE,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        return color + logging.Formatter.format(self, record)


class ColorLogger(logging.Logger):
    def __init__(self, name: str) -> None:
        level = NAME_TO_LEVEL[args.log_level.upper()]
        logging.Logger.__init__(self, name, level)
        color_formatter = ColorFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(color_formatter)
        self.addHandler(handler)

logging.setLoggerClass(ColorLogger)
_LOGGER = logging.getLogger("token_extractor")


class XiaomiCloudConnector:

    def __init__(self):
        self._agent = self.generate_agent()
        self._session = requests.session()
        self._ssecurity = None
        self._user_id = None
        self._c_user_id = None
        self._pass_token = None
        self._location = None
        self._service_token = None

        self._qr_image_url = None
        self._long_polling_url = None

    def login_step_1(self) -> bool:
        _LOGGER.debug("login_step_1")
        url = "https://account.xiaomi.com/longPolling/loginUrl"
        data = {
            '_qrsize': '240', 
            'qs': '%3Fsid%3Dxiaomiio%26_json%3Dtrue', 
            'callback': "https://sts.api.io.mi.com/sts", 
            '_hasLogo': 'false', 
            'sid': 'xiaomiio', 
            'serviceParam': '', 
            '_locale': 'zh_CN',
            '_dc': str(int(time.time() * 1000))
        }

        response = self._session.get(url, params=data)
        _LOGGER.debug(response.text)

        if response.status_code == 200:
            response_data = self.to_json(response.text)
            if "qr" in response_data:
                self._qr_image_url = response_data['qr']
                self._long_polling_url = response_data['lp']
                self._timeout = response_data['timeout']
                return True
        return False

    def login_step_2(self) -> bool:
        _LOGGER.debug("login_step_2")
        url = self._qr_image_url
        _LOGGER.debug("login_step_2: Image URL: %s", url)
        
        response = self._session.get(url)

        valid: bool = response is not None and response.status_code == 200

        if valid:
            try:
                image_content = response.content
                self.display_qrcode(image_content)
                print_if_interactive(f"{Fore.BLUE}QR code displayed. Please scan it with your Xiaomi device.")
                return True
            except Exception as e:
                _LOGGER.error(e)
        else:
            _LOGGER.error("login_step_2: HTTP status: %s; Response: %s", response.status_code, response.text[:500])
        return False

    def login_step_3(self) -> bool:
        _LOGGER.debug("login_step_3")

        url = self._long_polling_url
        _LOGGER.debug("Long polling URL: " + url)

        start_time = time.time()
        # Start long polling
        while True:
            try:
                response = self._session.get(url, timeout=10)
            except requests.exceptions.Timeout:
                _LOGGER.debug("Long polling timed out, retrying...")
                if time.time() - start_time > self._timeout:
                    _LOGGER.debug("Long polling timed out after {} seconds.".format(self._timeout))
                    break
                continue
            except requests.exceptions.RequestException as e:
                _LOGGER.error(f"An error occurred: {e}")
                break

            if response.status_code == 200:
                break
            else:
                _LOGGER.error("Long polling failed, retrying...")
        
        if response.status_code != 200:
            _LOGGER.error("Long polling failed with status code: " + str(response.status_code))
            return False

        _LOGGER.debug("Login successful!")
        _LOGGER.debug("Response data:")

        response_data = self.to_json(response.text)
        _LOGGER.debug(response_data)

        self._user_id = response_data['userId']
        self._ssecurity = response_data['ssecurity']
        self._c_user_id = response_data['cUserId']
        self._pass_token = response_data['passToken']
        self._location = response_data['location']
        
        _LOGGER.debug("User ID: " + str(self._user_id))
        _LOGGER.debug("Ssecurity: " + str(self._ssecurity))
        _LOGGER.debug("CUser ID: " + str(self._c_user_id))
        _LOGGER.debug("Pass token: " + str(self._pass_token))
        _LOGGER.debug("Pass token: " + str(self._location))

        return True
    
    def login_step_4(self) -> bool:
        _LOGGER.debug("login_step_4")
        _LOGGER.debug("Fetching service token...")
        
        if not (location := self._location):
            _LOGGER.error("No location found.")
            return False
        
        response = self._session.get(location, headers={'content-type': 'application/x-www-form-urlencoded'})
        if response.status_code != 200:
            return False

        self._service_token = response.cookies['serviceToken']
        _LOGGER.debug("Service token: " + str(self._service_token))
        return True

    def qr_login(self) -> bool:

        if not self.login_step_1():
            print_if_interactive(f"{Fore.RED}Unable to get login message.")
            return False

        if not self.login_step_2():
            print_if_interactive(f"{Fore.RED}Unable to get login QR Image.")
            return False

        if not self.login_step_3():
            print_if_interactive(f"{Fore.RED}Unable to login.")
            return False
        
        if not self.login_step_4():
            print_if_interactive(f"{Fore.RED}Unable to get service token.")
            return False

        return True

    def get_homes(self, country: str) -> dict | None:
        url = self.get_api_url(country) + "/v2/homeroom/gethome"
        params = {
            "data": '{"fg": true, "fetch_share": true, "fetch_share_dev": true, "limit": 300, "app_ver": 7}'}
        return self.execute_api_call_encrypted(url, params)

    def get_devices(self, country, home_id, owner_id) -> dict | None:
        url = self.get_api_url(country) + "/v2/home/home_device_list"
        params = {
            "data": '{"home_owner": ' + str(owner_id) +
            ',"home_id": ' + str(home_id) +
            ',  "limit": 200,  "get_split_device": true, "support_smart_home": true}'
        }
        return self.execute_api_call_encrypted(url, params)

    def get_dev_cnt(self, country) -> dict | None:
        url = self.get_api_url(country) + "/v2/user/get_device_cnt"
        params = {
            "data": '{ "fetch_own": true, "fetch_share": true}'
        }
        return self.execute_api_call_encrypted(url, params)

    def get_beaconkey(self, country, did) -> dict | None:
        url = self.get_api_url(country) + "/v2/device/blt_get_beaconkey"
        params = {
            "data": '{"did":"' + did + '","pdid":1}'
        }
        return self.execute_api_call_encrypted(url, params)

    def execute_api_call_encrypted(self, url, params) -> dict | None:
        headers = {
            "Accept-Encoding": "identity",
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
        }
        cookies = {
            "userId": str(self._user_id),
            "yetAnotherServiceToken": str(self._service_token),
            "serviceToken": str(self._service_token),
            "locale": "zh_CN",
            "timezone": "UTC+08:00",
            "is_daylight": "1",
            "dst_offset": "3600000",
            "channel": "MI_APP_STORE"
        }
        millis = round(time.time() * 1000)
        nonce = self.generate_nonce(millis)
        signed_nonce = self.signed_nonce(nonce)
        fields = self.generate_enc_params(url, "POST", signed_nonce, nonce, params, self._ssecurity)
        response = self._session.post(url, headers=headers, cookies=cookies, params=fields)
        if response.status_code == 200:
            decoded = self.decrypt_rc4(self.signed_nonce(fields["_nonce"]), response.text)
            return json.loads(decoded)
        return None

    @staticmethod
    def display_qrcode(content: bytes) -> None:
        nparr = np.frombuffer(content, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        detector = cv2.QRCodeDetector()
        result, points, _ = detector.detectAndDecode(image)
        if not result:
            raise ValueError("Invaild QR Image.")
        _LOGGER.debug("QR Content: " + result)
        qr = qrcode.QRCode(border=1)
        qr.add_data(result)
        qr.make(fit=True)
        qr.print_ascii(invert=True)

    @staticmethod
    def get_api_url(country: str) -> str:
        return "https://" + ("" if country == "cn" else (country + ".")) + "api.io.mi.com/app"

    def signed_nonce(self, nonce: str) -> str:
        hash_object = hashlib.sha256(base64.b64decode(self._ssecurity) + base64.b64decode(nonce))
        return base64.b64encode(hash_object.digest()).decode('utf-8')

    @staticmethod
    def generate_nonce(millis: int) -> str:
        nonce_bytes = os.urandom(8) + (int(millis / 60000)).to_bytes(4, byteorder='big')
        return base64.b64encode(nonce_bytes).decode()

    @staticmethod
    def generate_agent() -> str:
        agent_id = "".join(
            map(lambda i: chr(i), [random.randint(65, 69) for _ in range(13)])
        )
        random_text = "".join(map(lambda i: chr(i), [random.randint(97, 122) for _ in range(18)]))
        return f"{random_text}-{agent_id} APP/com.xiaomi.mihome APPV/10.5.201"

    @staticmethod
    def generate_enc_signature(url:str, method:str, signed_nonce: str, params: dict[str, str]) -> str:
        signature_params = [method.upper(), url.split("com")[1].replace("/app/", "/")]
        for k, v in params.items():
            signature_params.append(f"{k}={v}")
        signature_params.append(signed_nonce)
        signature_string = "&".join(signature_params)
        return base64.b64encode(hashlib.sha1(signature_string.encode('utf-8')).digest()).decode()

    @staticmethod
    def generate_enc_params(url: str, method:str, signed_nonce: str, nonce:str, params: dict[str, str], ssecurity: str):
        params['rc4_hash__'] = XiaomiCloudConnector.generate_enc_signature(url, method, signed_nonce, params)
        for k, v in params.items():
            params[k] = XiaomiCloudConnector.encrypt_rc4(signed_nonce, v)
        params.update({
            'signature': XiaomiCloudConnector.generate_enc_signature(url, method, signed_nonce, params),
            'ssecurity': ssecurity,
            '_nonce': nonce,
        })
        return params

    @staticmethod
    def to_json(response_text: str) -> dict:
        return json.loads(response_text.replace("&&&START&&&", ""))

    @staticmethod
    def encrypt_rc4(password, payload):
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return base64.b64encode(r.encrypt(payload.encode())).decode()

    @staticmethod
    def decrypt_rc4(password: str, payload: str) -> bytes:
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return r.encrypt(base64.b64decode(payload))


def print_if_interactive(value: str="") -> None:
    if not args.non_interactive:
        print(value)


def print_tabbed(value: str, tab: int) -> None:
    print_if_interactive(" " * tab + value)


def print_entry(key: str, value: str, tab: int) -> None:
    if value:
        print_tabbed(f'{Fore.YELLOW}{key + ":": <10}{Style.RESET_ALL}{value}', tab)


def print_banner() -> None:
    print_if_interactive(Fore.YELLOW + Style.BRIGHT + r"""
                               Xiaomi Cloud
___ ____ _  _ ____ _  _ ____    ____ _  _ ___ ____ ____ ____ ___ ____ ____ 
 |  |  | |_/  |___ |\ | [__     |___  \/   |  |__/ |__| |     |  |  | |__/ 
 |  |__| | \_ |___ | \| ___]    |___ _/\_  |  |  \ |  | |___  |  |__| |  \ 
""" + Style.NORMAL +
"""                                                        by Piotr Machowski 

    """)


def main() -> None:
    print_banner()
    servers_str = ", ".join(SERVERS)
    if args.server is not None:
        server = args.server
    elif args.non_interactive:
        server = ""
    else:
        print_if_interactive(f"Server {Fore.BLUE}(one of: {servers_str}; Leave empty to check all available){Style.RESET_ALL}:")
        server = input()
        while server not in ["", *SERVERS]:
            print_if_interactive(f"{Fore.RED}Invalid server provided. Valid values: {servers_str}")
            print_if_interactive("Server:")
            server = input()

    print_if_interactive()
    if not server == "":
        servers_to_check = [server]
    else:
        servers_to_check = [*SERVERS]
    connector = XiaomiCloudConnector()
    print_if_interactive(f"{Fore.BLUE}Starting QR code login...")
    print_if_interactive()
    logged = connector.qr_login()
    print_if_interactive()
    if logged:
        print_if_interactive(f"{Fore.GREEN}Logged in.")
        print_if_interactive()
        output = []
        for current_server in servers_to_check:
            all_homes = []
            homes = connector.get_homes(current_server)
            if homes is not None:
                for h in homes['result']['homelist']:
                    all_homes.append({'home_id': h['id'], 'home_owner': connector._user_id})
            dev_cnt = connector.get_dev_cnt(current_server)
            if dev_cnt is not None:
                for h in dev_cnt["result"]["share"]["share_family"]:
                    all_homes.append({'home_id': h['home_id'], 'home_owner': h['home_owner']})

            if len(all_homes) == 0:
                print_if_interactive(f'{Fore.RED}No homes found for server "{current_server}".')

            for home in all_homes:
                devices = connector.get_devices(current_server, home['home_id'], home['home_owner'])
                home["devices"] = []
                if devices is not None:
                    if devices["result"]["device_info"] is None or len(devices["result"]["device_info"]) == 0:
                        print_if_interactive(f'{Fore.RED}No devices found for server "{current_server}" @ home "{home["home_id"]}".')
                        continue
                    print_if_interactive(f'Devices found for server "{current_server}" @ home "{home["home_id"]}":')
                    for device in devices["result"]["device_info"]:
                        device_data = {**device}
                        print_tabbed(f"{Fore.BLUE}---------", 3)
                        if "name" in device:
                            print_entry("NAME", device["name"], 3)
                        if "did" in device:
                            print_entry("ID", device["did"], 3)
                            if "blt" in device["did"]:
                                beaconkey = connector.get_beaconkey(current_server, device["did"])
                                if beaconkey and "result" in beaconkey and "beaconkey" in beaconkey["result"]:
                                    print_entry("BLE KEY", beaconkey["result"]["beaconkey"], 3)
                                    device_data["BLE_DATA"] = beaconkey["result"]
                        if "mac" in device:
                            print_entry("MAC", device["mac"], 3)
                        if "localip" in device:
                            print_entry("IP", device["localip"], 3)
                        if "token" in device:
                            print_entry("TOKEN", device["token"], 3)
                        if "model" in device:
                            print_entry("MODEL", device["model"], 3)
                        home["devices"].append(device_data)
                    print_tabbed(f"{Fore.BLUE}---------", 3)
                    print_if_interactive()
                else:
                    print_if_interactive(f"{Fore.RED}Unable to get devices from server {current_server}.")
            output.append({"server": current_server, "homes": all_homes})
        if args.output:
            with open(args.output, "w") as f:
                f.write(json.dumps(output, indent=4))
    else:
        print_if_interactive(f"{Fore.RED}Unable to log in.")

    if not args.non_interactive:
        print_if_interactive()
        print_if_interactive("Press ENTER to finish")
        input()


if __name__ == "__main__":
    main()
