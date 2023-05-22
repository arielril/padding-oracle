import os
import sys
from urllib.parse import urlencode

import urllib3

TARGET = "http://crypto-class.appspot.com/po?"


def split_block_size(msg: str, b_size=16):
    return [msg[i : i + b_size] for i in range(0, len(msg), b_size)]


def gen_random_block(block_len: int) -> str:
    return os.urandom(block_len).hex()


def xor_hex(a: str, b: str) -> str:
    return "{res:032x}".format(res=(int(a, 16) ^ int(b, 16)))


class PaddingOracle(object):
    def query(self, cipher) -> bool:
        target = TARGET + urlencode({"er": cipher})

        print(f"requesting {target}")
        resp = urllib3.request("GET", target)
        # print("resp -> ", resp.__dict__)

        # print("We got: ", resp.status)
        if resp.status == 404:
            # print("-----------------------")
            # print("good padding")
            # print("-----------------------")
            return True  # good padding
        # print("bad padding")
        return False  # bad padding


if __name__ == "__main__":
    try:
        block_size = 16
        cipher = bytes.fromhex(sys.argv[1])

        po = PaddingOracle()

        blocks = [cipher[i : i + block_size] for i in range(0, len(cipher), block_size)]
        iv_block = blocks[0]

        final_message = []

        for block_pos, cipher_block in enumerate(blocks):
            print(f"{block_pos} -> {cipher_block}")

            message_block = [""] * (len(blocks) - 1)

            # iterate over each byte from the block
            for possible_pad, byte_value in enumerate(reversed(cipher_block), 1):
                # print(f"{possible_pad=} -> {byte_value=}")

                guess_padding: str = (
                    "00" * (block_size - possible_pad)
                    + (f"{possible_pad:02x}") * possible_pad
                )

                for byte_guess in range(0, 256, 1):
                    print(f"{byte_guess=}")
                    test_block = f"{cipher_block[0 : block_size - possible_pad].hex()}{byte_value ^ byte_guess}"
                    # print(f"{test_block=}")

                    decrypt_attempt = (
                        "".join([b.hex() for b in blocks[:block_pos]])
                        + xor_hex(test_block, guess_padding)
                        + blocks[block_pos + 1].hex()
                    )
                    # print(f"{decrypt_attempt=}")

                    found_good_padding = po.query(decrypt_attempt)
                    if found_good_padding:
                        print(f"found good padding {byte_guess:02x}")
                        message_block.insert(0, chr(byte_value ^ byte_guess))
                        break
                    elif not found_good_padding and byte_guess == 255:
                        print("exhausted tries ;(")
                        message_block.insert(0, chr(byte_value ^ 9))

            print(f"{message_block=}")
            final_message[block_pos] = message_block

        print(f"final result {''.join(final_message)}")

    except KeyboardInterrupt:
        print("exiting...")
