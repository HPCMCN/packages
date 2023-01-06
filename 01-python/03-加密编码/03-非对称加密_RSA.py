# -*- coding:utf-8 -*-
# author: HPCM
# time: 2023/1/5 23:39
# file: 03-非对称加密_RSA.py
import os
import warnings

try:
    # noinspection PyUnresolvedReferences
    from Crypto.PublicKey import RSA
    # noinspection PyUnresolvedReferences
    from Crypto.Cipher import PKCS1_OAEP, AES
except ImportError:
    # noinspection PyUnresolvedReferences
    from Cryptodome.PublicKey import RSA
    # noinspection PyUnresolvedReferences
    from Cryptodome.Cipher import PKCS1_OAEP, AES


class RsaCryptFile(object):
    """Rsa crypt files"""

    def __init__(self, secret_key=None, sign_suffix=None):
        self.secret_key = secret_key or "1****6"
        self.encrypt_suffix = sign_suffix or ".hpcm"
        self.encrypt_path = "en"
        self.decrypt_path = "de"
        self.public_file = "public.pem"
        self.private_file = "private.pem"
        self.read_size = 16 * 1024
        self.session_size = 32
        self.nonce_len = 16
        self.aes_mode = AES.MODE_EAX

    def generate_key(self):
        """generate rsa private and public key"""
        # rsa算法生成实例
        rsa = RSA.generate(2048, os.urandom)

        # 秘钥对的生成
        private_pem = rsa.export_key(passphrase=self.secret_key)
        public_pem = rsa.publickey().exportKey()  # 公钥

        # 公钥
        with open(self.public_file, "wb") as f:
            f.write(public_pem)

        # 私钥
        with open(self.private_file, "wb") as f:
            f.write(private_pem)
        msg = "you must save file `{}` and secret key `{}` !!!".format(self.private_file, self.secret_key)
        warnings.warn(msg)
        warnings.warn(msg)
        warnings.warn(msg)

    def generate_public(self):
        """利用私钥生成公钥"""
        private = RSA.import_key(self.get_private(), passphrase=self.secret_key)
        public_pem = private.publickey().exportKey()
        with open(self.public_file, "wb") as f:
            f.write(public_pem)
        print("generate public success!")

    def get_private(self):
        """读取私钥信息"""
        with open(self.private_file, "rb") as f:
            return f.read()

    def get_public(self):
        """读取公钥信息"""
        with open(self.public_file, "rb") as f:
            return f.read()

    def get_public_rsa(self):
        """导入公钥"""
        public = RSA.import_key(self.get_public())
        return PKCS1_OAEP.new(public)

    def get_private_rsa(self):
        """导入私钥"""
        private = RSA.import_key(self.get_private(), passphrase=self.secret_key)
        return PKCS1_OAEP.new(private)

    def get_decrypt_object(self, cipher_rsa, key):
        """拆解密文头部信息保存的, key_bytes和nonce(解密对象初始化需要的数据)
        :param cipher_rsa: rsa的私钥对象
        :param key: 待拆解的加密时混淆使用的随机字符串
        :return AES object
        """
        key_bytes = key[:-self.nonce_len]
        nonce = key[-self.nonce_len:]
        res = cipher_rsa.decrypt(key_bytes)
        return self.get_crypt_cipher(res, nonce)

    def get_encrypt_object(self, cipher_rsa):
        """组合封装加密对象初始化的参数到文件中
        :param cipher_rsa: rsa的私钥对象
        :return tuple, (AES object,RSA加密后的key)
        """
        key = os.urandom(self.session_size)
        res = cipher_rsa.encrypt(key)
        cipher = self.get_crypt_cipher(key)
        return cipher, res

    @staticmethod
    def get_crypt_cipher(key, nonce=None):
        """创建一个AES算法加密的对称性加密对象, 用来加密公钥混淆key
        :param key: bytes, AES加密数据的key
        :param nonce: bytes, AES加密数据的随机字符串, 对于组合消息/密钥，它必须是唯一的
        :return AES object
        """
        if nonce:
            crypt = AES.new(key, AES.MODE_EAX, nonce=nonce)
        else:
            crypt = AES.new(key, AES.MODE_EAX)
        return crypt

    def rsa_encrypt(self, cipher_rsa, file_name, save_file, restore_name=True):
        """RSA加密文件, 并将混淆key拼接到文件开头部分
        :param cipher_rsa: RSA公钥对象
        :param file_name: 需要加密的文件
        :param save_file: 将加密后的文件保存的位置
        :param restore_name: 是否对加密文件添加特殊后缀
        """
        if restore_name:
            save_file = save_file + self.encrypt_suffix
        base_file_path = os.path.dirname(save_file)
        if not os.path.exists(base_file_path):
            os.makedirs(base_file_path)
        with open(file_name, "rb") as f1, open(save_file, "wb") as f2:
            cipher, key = self.get_encrypt_object(cipher_rsa)
            kc = key + cipher.nonce
            f2.write("{:05d}".format(len(kc)).encode() + kc)
            while True:
                content = f1.read(self.read_size)
                if not content:
                    break
                en_content = cipher.encrypt(content)
                f2.write(en_content)
        print("encrypt {} success!".format(save_file))

    def rsa_decrypt(self, cipher_rsa, file_name, save_file, restore_name=True):
        """RSA的私钥进行解密
        :param cipher_rsa: RSA私钥对象
        :param file_name: 需要解密的文件
        :param save_file: 将解密后的文件保存的位置
        :param restore_name: 是否对解密文件去除加密时采用的特殊后缀信息
        """
        if restore_name and save_file.endswith(self.encrypt_suffix):
            save_file = save_file[:-len(self.encrypt_suffix)]
        base_file_path = os.path.dirname(save_file)
        if not os.path.exists(base_file_path):
            os.makedirs(base_file_path)
        with open(file_name, "rb") as f1, open(save_file, "wb") as f2:
            size = f1.read(5)
            session_key = f1.read(int(size))
            cipher = self.get_decrypt_object(cipher_rsa, session_key)
            while True:
                content = f1.read(self.read_size)
                if not content:
                    break
                de_content = cipher.decrypt(content)
                f2.write(de_content)
        print("decrypt {} success!".format(save_file))

    def encrypt_file(self, file, save_file):
        """使用RSA public key对文件进行加密
        :param file: str, 待加密的文件名
        :param save_file: str, 加密后的文件名
        """
        cipher_rsa = self.get_public_rsa()
        self.rsa_encrypt(cipher_rsa, file, save_file)

    def decrypt_file(self, file, save_file):
        """使用RSA private key对文件进行解密
        :param file: str, 待解密的文件名
        :param save_file: str, 解密后的文件名
        """
        cipher_rsa = self.get_private_rsa()
        self.rsa_decrypt(cipher_rsa, file, save_file)

    def walk_paths(self, path, sp=""):
        """遍历全部文件
        :param path: 当前遍历目录的绝对路径
        :param sp: basename
        :return generate object ==> (当前文件, basename)
        """
        sp = sp if sp else os.path.basename(path)
        if os.path.isfile(path):
            yield path, sp
        else:
            for son_path in os.listdir(path):
                abs_son_path = os.path.join(path, son_path)
                yield from self.walk_paths(abs_son_path, os.path.join(sp, son_path))

    def decrypt_paths(self, path, ignore_error=True):
        """解密指定目录下的全部文件
        :param path: 需要加密的目录
        :param ignore_error: 是否忽略加密过程中遇到的部分文件报错, 默认是
        """
        paths = list(self.walk_paths(path))
        for i, (file_name, save_file) in enumerate(paths):
            current_progress = "{:.2f}".format((i + 1) / len(paths) * 100)
            print("{} ==>\t".format(current_progress), sep="", end="")
            try:
                self.decrypt_file(file_name, os.path.join(self.decrypt_path, save_file))
            except Exception as e:
                print(e)
                if ignore_error:
                    import traceback
                    traceback.print_exc()
                else:
                    break

    def encrypt_paths(self, path, ignore_error=True):
        """加密指定目录下的全部文件
        :param path: 需要解密的目录
        :param ignore_error: 是否忽略解密过程中遇到的部分文件报错, 默认是
        """
        paths = list(self.walk_paths(path))
        for i, (file_name, save_file) in enumerate(paths):
            current_progress = "{:.2f}".format((i + 1) / len(paths) * 100)
            print("{} ==>\t".format(current_progress), sep="", end="")
            try:
                self.encrypt_file(file_name, os.path.join(self.encrypt_path, save_file))
            except Exception as e:
                print(e)
                if ignore_error:
                    import traceback
                    traceback.print_exc()
                else:
                    break


if __name__ == '__main__':
    choices_mapping = {
        "1": lambda obj: obj.encrypt_paths(input("请输入加密文件/路径: \n")),
        "2": lambda obj: obj.decrypt_paths(input("请输入解密文件/路径: \n")),
        "3": lambda obj: obj.generate_key(),
        "4": lambda obj: obj.generate_public(),
    }

    sk = input("请输入秘钥的密码: ")
    sn = input("请输入加密后文件尾缀: ")

    while True:
        rcf = RsaCryptFile(secret_key=sk, sign_suffix=sn)
        choice = input("请选择你要做的操作: \n1. 加密\n2. 解密\n3. 生成公私钥对\n4. 由秘钥生成公钥\n\n任意键退出...")
        try:
            func = choices_mapping[choice](rcf)
        except KeyError:
            break
