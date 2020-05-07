import ctypes
import re
import argparse
import logging

from base64 import b64decode
from urllib import parse

import conf


class DecryptionFailed(Exception):
    pass


def ursnif_beacon_decryptor():
    parser = argparse.ArgumentParser(description='Ursnif Check-in Decryptor')
    parser.add_argument("-u", "--url", required=False,
                        help='full path url of suspected ursnif check-in')
    parser.add_argument("-o", "--only-encrypted-data", required=False,
                        help='use this if you have the encrypted path only. This is useful for the 3.0 version that'
                             ' does not use GET method')
    parser.add_argument("-k", "--key", required=False, default=None,
                        help="key required to decrypt. If not inserted, the script would try known ones")
    parser.add_argument("-d", "--debug", default=False, action="store_true",
                        help='debug mode')

    args = parser.parse_args()
    logger = get_logger(args.debug)
    key = args.key
    url = args.url
    try:
        if args.url:
            if not url.startswith('http'):
                url = "http://" + url
            url_parsed = parse.urlparse(url)
            c2 = url_parsed.netloc
            path = url_parsed.path
            logger.info("c2 domain: '{}'".format(c2))
            logger.info("path to analyze: {}".format(path))

            found_file_type = False
            for known_file_type in conf.KNOWN_FILE_TYPES:
                if path.endswith('.{}'.format(known_file_type)):
                    found_file_type = True
                    break
            if not found_file_type:
                logger.warning("CARE! the URL you sent does not match known file types used by Ursnif for the Check-in: {}"
                               "".format(conf.KNOWN_FILE_TYPES))

            found_first_path = False
            for known_first_path_item in conf.KNOWN_FIRST_PATH:
                if path.startswith('/{}/'.format(known_first_path_item)):
                    found_first_path = True
                    break
            if not found_first_path:
                logger.warning("CARE! the URL you sent has an URI that does not match known used by malware: {}"
                               "".format(conf.KNOWN_FIRST_PATH))

            to_decrypt_path = None
            regex = re.compile("^/\w+/(.+)\.")
            match = re.match(regex, path)
            if match:
                to_decrypt_path = match.group(1)

            if not to_decrypt_path:
                raise DecryptionFailed("uri path was not extracted")
        elif args.only_encrypted_data:
            to_decrypt_path = args.only_encrypted_data
            logger.info("path to analyze: {}".format(to_decrypt_path))
        else:
            raise DecryptionFailed("you must provide either -u or -o option")

        logger.debug(to_decrypt_path)

        # first step, remove slashes
        to_decrypt_path = to_decrypt_path.replace('/', '')
        logger.debug(to_decrypt_path)

        # second step, restore / and + needed for base64 encoding
        to_decrypt_path = to_decrypt_path.replace('_2F', '/')
        to_decrypt_path = to_decrypt_path.replace('_2B', '+')
        # version 2.50 added the 0A and 0D
        to_decrypt_path = to_decrypt_path.replace('_0A', '\n')
        to_decrypt_path = to_decrypt_path.replace('_0D', '\r')
        logger.debug(to_decrypt_path)

        # restore the padding
        b64_padding = 4
        non_aligned_chars = len(to_decrypt_path) % b64_padding
        if non_aligned_chars:
            padding_to_add = b64_padding - non_aligned_chars
            to_decrypt_path += "=" * padding_to_add
        logger.debug(to_decrypt_path)

        # base64 decode
        bytes_encoded = b64decode(to_decrypt_path)
        logger.debug(bytes_encoded)
        length_bytes_encoded = len(bytes_encoded)
        logger.debug(length_bytes_encoded)

        # import shared library
        library = ctypes.CDLL("./Driver.so")
        # import decrypt function
        decrypt_f = getattr(library, 'decrypt')
        decrypt_f.restype = ctypes.c_void_p
        decrypt_f.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]

        # adjust length to block size (16)
        block_size = 16
        non_aligned_chars = length_bytes_encoded % block_size
        if non_aligned_chars:
            padding_to_add = block_size - non_aligned_chars
            bytes_encoded += b"\x00" * padding_to_add
            length_bytes_encoded = len(bytes_encoded)

        if key:
            keys = [key]
        else:
            # if not specified, load configured list of known keys
            keys = conf.KNOWN_KEYS

        for key in keys:
            try:
                key_mutable = ctypes.create_string_buffer(str.encode(key))
                logger.debug("encrypted: {}".format(bytes_encoded))
                logger.debug("key: {}".format(key_mutable.value))

                returned = decrypt_f(bytes_encoded, length_bytes_encoded, key_mutable.value)
                b_string_decoded = ctypes.cast(returned, ctypes.c_char_p).value

                logger.debug("decoded: {}".format(b_string_decoded))
                decoded_params = b_string_decoded.decode()
                logger.info("Congrats! decoded data: {}".format(decoded_params))

                # free allocated memory
                free_f = getattr(library, 'freeme')
                free_f.argtypes = [ctypes.c_void_p]
                free_f.restype = None
                free_f(returned)
            except Exception as e:
                logger.exception("failed decryption with key {}. Error: {}".format(key, e))
            else:
                break

    except DecryptionFailed as e:
        logger.error("failed decryption. Error: {}".format(e))

    except Exception as e:
        logger.exception("failed decryption. Error: {}".format(e))


def get_logger(debug_mode):
    if debug_mode:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    sh = logging.StreamHandler()
    formatter = logging.Formatter('[%(asctime)s - %(levelname)s] %(message)s',
                                  '%Y-%m-%d %H:%M:%S')
    sh.setFormatter(formatter)
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    logger.addHandler(sh)
    return logger


if __name__ == "__main__":
    ursnif_beacon_decryptor()
