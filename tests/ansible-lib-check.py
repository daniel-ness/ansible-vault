#!/bin/env python

import os
from binascii import hexlify
from binascii import unhexlify
from ansible.parsing.vault import (
  parse_vaulttext_envelope,
  parse_vaulttext,
  VaultEditor,
  VaultLib,
  VaultSecret,
  VaultAES256,
)
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher as C_Cipher, algorithms, modes
)

dir = os.path.dirname(__file__)
filename = dir + '/files/OnePointOneStringNoTag.txt'
vault_text = open(filename, 'r').read()

lib = VaultLib(secrets=[['default', VaultSecret("daniel-ness/ansible-vault")]])
print lib.decrypt(vault_text)

plaintext, vault_id, vault_secret = lib.decrypt_and_get_vault_id(vault_text)
print plaintext
print vault_text
b_vaulttext, dummy, cipher_name, vault_id = parse_vaulttext_envelope(vault_text)
print b_vaulttext
cipher_text, salt, crypted_hmac = parse_vaulttext(b_vaulttext)

print("Cipher Text: " + hexlify(cipher_text))
print("Salt: " + hexlify(salt))
print("HMAC: " + crypted_hmac)


aes = VaultAES256()
key1, key2, iv = aes._gen_key_initctr("daniel-ness/ansible-vault", salt)

print("Key1: " + hexlify(key1))
print("Key2: " + hexlify(key2))
print("IV: " + hexlify(iv))

print ("pre decrypt:")
print(unhexlify(hexlify(cipher_text)))
cipher = C_Cipher(algorithms.AES(key1), modes.CTR(iv), default_backend())
decryptor = cipher.decryptor()
unpadder = padding.PKCS7(128).unpadder()
plaintext = unpadder.update(decryptor.update(cipher_text) + decryptor.finalize()) + unpadder.finalize()

cipher = C_Cipher(algorithms.AES(key1), modes.CTR(iv), default_backend())
decryptor = cipher.decryptor()
unpadder = padding.PKCS7(128).unpadder()
plaintext = decryptor.update(cipher_text) #+ decryptor.finalize()
print(default_backend())
print("Without padding")
print(plaintext)

print plaintext
plaintext = aes._decrypt_cryptography(cipher_text, crypted_hmac, key1, key2, iv)
print plaintext


b_hmac, b_cipher_text = VaultAES256._encrypt_cryptography(plaintext, key1, key2, iv)
print b_hmac
print b_cipher_text

cipher = C_Cipher(algorithms.AES(key1), modes.CTR(iv), default_backend())
encryptor = cipher.encryptor()
cipher_text = encryptor.update(plaintext)
cipher_text += encryptor.finalize()
print hexlify(cipher_text)




#aes.
padder = padding.PKCS7(algorithms.AES.block_size).padder()
padded_text = padder.update(plaintext) + padder.finalize()
print "'" + padded_text + "'"

editor = VaultEditor(lib)
#editor.decrypt_file(filename)



