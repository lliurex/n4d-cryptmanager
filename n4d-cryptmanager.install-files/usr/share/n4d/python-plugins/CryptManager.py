import xmlrpc.client
import ssl

import os
import secrets
import base64
import copy

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


import n4d.server.core
import n4d.responses


class CryptManager:
	
    def _mk_dir(self, dir_name):
        if not os.path.isdir(dir_name):
            os.makedirs(dir_name)
            os.chmod(dir_name, 0o700)
    # def _mk_dir

    def _mk_file(self, file_name):
        dir_name = os.path.dirname(file_name)
        self._mk_dir(dir_name)

        if not os.path.exists(file_name):
            open(file_name, 'a').close()
            os.chmod(file_name, 0o600)

    # def _mk_file

    def __init__(self):
        self.core=n4d.server.core.Core.get_core()

        # dirs
        self.base_dir = "/var/lib/n4d-CryptManager"
        self.keys_dir = self.base_dir + "/keys"
        for d in [self.base_dir, self.keys_dir]:
            self._mk_dir(d)

        self.enc_methods = [ "AES256-GCM" ]
        self.enc_default = self.enc_methods[0]
		
    # def init

    def startup(self,options):
        # executed when launching n4d
        pass
	
	#def startup
	
    def create_key(self, key_name):
        key_dir = self.keys_dir+"/"+key_name
        self._mk_dir(key_dir)
        key_file = key_dir+"/"+key_name+".key32"

        # skip key generation if file already exists
        ret = True
        if not (os.path.exists(key_file) and os.path.getsize(key_file) > 0) :
            self._mk_file(key_file)
            # Generate a random secret key of 32 bytes for AES256
            key = secrets.token_bytes(32)
            with open(key_file, 'wb') as f:
                f.write(key)

            if not (os.path.exists(key_file) and os.path.getsize(key_file) > 0) :
                ret = False

        return n4d.responses.build_successful_call_response( ret, copy.deepcopy(key_name) )

    # def create_key

    def _read_key(self, key_name, enc_method):
        # TODO: manage alternative encryption methods and keys
        key_file = self.keys_dir+"/"+key_name+"/"+key_name+".key32"
        with open(key_file, "rb") as f:
            # Read the entire content of the file
            key = f.read()

        return key

    # def _read_key

    def _check_method(self, enc_method):
        if not enc_method:
            # use default
            enc_method = self.enc_default

        if not (enc_method in self.enc_methods):
            return None

        return enc_method

    # def _check_method

    def _var_key_name(self, var_name):
        return "n4dvar_"+var_name

    # def create_varkey

    def encode_text(self, key_name, text, enc_method=""):
        enc_method = self._check_method(enc_method)
        if not enc_method:
            return n4d.responses.build_failed_call_response("", "Invalid encryption method")

        self.create_key(key_name)
        key = self._read_key(key_name, enc_method)

        nonce = secrets.token_bytes(12)  # GCM mode needs 12 fresh bytes every time
        byte_encoded = nonce + AESGCM(key).encrypt(nonce, text.encode('utf-8'), b"")
        text_encoded = base64.b64encode(byte_encoded).decode('utf-8')

        return n4d.responses.build_successful_call_response( copy.deepcopy(text_encoded), copy.deepcopy(enc_method) )

    # def encode_text

    def decode_text(self, key_name, text_encoded, enc_method=""):
        enc_method = self._check_method(enc_method)
        if not enc_method:
            return n4d.responses.build_failed_call_response("", "Invalid encryption method")

        key = self._read_key(key_name, enc_method)

        byte_encoded = base64.b64decode(text_encoded.encode('utf-8'))
        # TODO: manage alternative encryption methods
        # Decrypt (raises InvalidTag if using wrong key or corrupted ciphertext)
        byte_decoded = AESGCM(key).decrypt(byte_encoded[:12], byte_encoded[12:], b"")
        text_decoded = byte_decoded.decode('utf-8')

        return n4d.responses.build_successful_call_response( copy.deepcopy(text_decoded), copy.deepcopy(enc_method) )

    # def decode_text

    def encode_variable(self, var_name, var_text):
        key_name = self._var_key_name(var_name)
        enc_method = self.enc_default
        key_dir = self.keys_dir+"/"+key_name
        method_file = key_dir+"/"+key_name+".method"

        var_text_encoded = self.encode_text(key_name, var_text, enc_method).get('return', None)

        if self.core.set_variable(var_name,var_text_encoded,{"info":enc_method}) :
            self._mk_file(method_file)
            with open(method_file, "w") as f:
                f.write(enc_method)

            return n4d.responses.build_successful_call_response( copy.deepcopy(var_text_encoded), copy.deepcopy(enc_method) )
        else :
            # remove method file
            if os.path.exists(method_file):
                os.remove(method_file)

        return n4d.responses.build_failed_call_response("", "Error writing variable")
            
    # def set_variable

    def decode_variable(self, var_name):
        key_name = self._var_key_name(var_name)
        key_dir = self.keys_dir+"/"+key_name
        method_file = key_dir+"/"+key_name+".method"
        with open(method_file, "r") as text_file:
            # Read the entire content of the file
            enc_method = text_file.read()

        var_text_encoded = self.core.get_variable(var_name).get('return', None)
        if not var_text_encoded:
            return n4d.responses.build_failed_call_response("", "Error reading variable")

        var_text_decoded = self.decode_text(key_name, var_text_encoded, enc_method).get('return', None)
        return n4d.responses.build_successful_call_response( copy.deepcopy(var_text_decoded), copy.deepcopy(enc_method) )

    # def get_variable

#class CryptManager
