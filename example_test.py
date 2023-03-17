import time as get_time
import execute_crypto

obj=execute_crypto.ExecuteCrypto()
symmetric_key,public_key_sender_rsa, private_key_sender_rsa,public_key_receiver_rsa, private_key_receiver_rsa,public_key_sender_ecc, private_key_sender_ecc=obj.generate_keys()
nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac,nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm=obj.generate_nonces()
plaintext='Charizard was designed by Atsuko Nishida for the first generation of Pocket Monsters games Red and Green, which were localized outside Japan as Pokemon Red and Blue. Charizard was designed before Charmander, the latter being actually based on the former. Originally called lizardon in Japanese, Nintendo decided to give the various Pokemon species clever and descriptive names related to their appearance or features when translating the game for western audiences as a means to make the characters more relatable to American children. As a result, they were renamed Charizard, a portmanteau of the words charcoal or char and lizard.'

print("\n\n-----------------------------------------------------------------------\n\n")
#get_time diffrence calculation for AES-128-CBC-ENC
start = get_time.time()
ctxt1=obj.encrypt('AES-128-CBC-ENC',symmetric_key,plaintext,nonce_aes_cbc)
end=get_time.time()
print('Execution time for AES-128-CBC Encryption',(end-start)*1000)
print('Ciphertext length=',len(ctxt1))
print('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")

#Time diffrence calculation for AES-128-CBC-DEC
start = get_time.time()
ptxt1=obj.decrypt('AES-128-CBC-DEC',symmetric_key,ctxt1,nonce_aes_cbc)
end=get_time.time()
print('Execution time for AES-128-CBC Decryption',(end-start)*1000)
print('Ciphertext length=',len(ctxt1))
print('Plaintext length=',len(ptxt1))

print("\n\n-----------------------------------------------------------------------\n\n")

# 1. AES-128-CTR
start = get_time.time()
ctxt2=obj.encrypt('AES-128-CTR-ENC',symmetric_key,plaintext,nonce_aes_ctr)
end=get_time.time()
print('Execution time AES-128-CTR Encryption',(end-start)*1000)
print('Ciphertext length=',len(ctxt2))
print('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")



#Time diffrence calculation for AES-128-CTR-DEC
start = get_time.time()
ptxt2=obj.decrypt('AES-128-CTR-DEC',symmetric_key,ctxt2,nonce_aes_ctr)
end=get_time.time()
print('Execution time for AES-128-CBC Decryption',(end-start)*1000)
print('Ciphertext length=',len(ctxt2))
print('Plaintext length=',len(ptxt2))

print("\n\n-----------------------------------------------------------------------\n\n")

#Time diffrence calculation for RSA-2048-ENC
start = get_time.time()
ctxt3=obj.encrypt('RSA-2048-ENC', public_key_receiver_rsa ,symmetric_key,nonce_encrypt_rsa)
end=get_time.time()
print('Execution time for RSA-2048 Encryption',(end-start)*1000)
print('Ciphertext length=',len(ctxt3))
print('Plaintext length=',len(symmetric_key))

print("\n\n-----------------------------------------------------------------------\n\n")

#Time diffrence calculation for RSA-2048-DEC
start = get_time.time()
ptxt3=obj.decrypt('RSA-2048-DEC',private_key_receiver_rsa,ctxt3,nonce_encrypt_rsa)
end=get_time.time()
print('Execution time for AES-128-CBC Decryption',(end-start)*1000)
print('Ciphertext length=',len(ctxt3))
print('Plaintext length=',len(ptxt3))

print("\n\n-----------------------------------------------------------------------\n\n")

#Time diffrence calculation for AES-128-CMAC-GEN
start = get_time.time()
tag1=obj.generate_auth_tag('AES-128-CMAC-GEN',symmetric_key,plaintext,nonce_aes_cmac)
end=get_time.time()
print('Execution time AES-128-CMAC-GEN ',(end-start)*1000)
print('Tag length=',len(tag1))
print('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")

#Time diffrence calculation for AES-128-CMAC-VRF
start = get_time.time()
obj.verify_auth_tag('AES-128-CMAC-VRF',symmetric_key,plaintext,nonce_aes_cmac,tag1)
end=get_time.time()
print('Execution time for AES-128-CMAC-VRF ',(end-start)*1000)
#print('Tag length=',len(tag1))
#print('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")


#Time diffrence calculation for SHA3-256-HMAC-GEN
start = get_time.time()
tag2=obj.generate_auth_tag('SHA3-256-HMAC-GEN',symmetric_key,plaintext,nonce_hmac)
end=get_time.time()
print('Execution time for SHA3-256-HMAC-GEN ',(end-start)*1000)
print('Tag length=',len(tag2))
print('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")

#Time diffrence calculation for SHA3-256-HMAC-VRF
start = get_time.time()
obj.verify_auth_tag('SHA3-256-HMAC-VRF',symmetric_key,plaintext,nonce_hmac,tag2)
end=get_time.time()
print('Execution time for SHA3-256-HMAC-VRF ',(end-start)*1000)
#print('Tag length=',len(tag2))
#print('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")


#get_time diffrence calculation for RSA-2048-SHA3-256-SIG-GEN
start = get_time.time()
tag3=obj.generate_auth_tag('RSA-2048-SHA3-256-SIG-GEN',private_key_sender_rsa,plaintext,nonce_hmac)
end=get_time.time()
print('Execution time for RSA-2048-SHA3-256-SIG-GEN ',(end-start)*1000)
print('Tag length=',len(tag3))
print('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")

#Time diffrence calculation for RSA-2048-SHA3-256-SIG-VRF
start = get_time.time()
obj.verify_auth_tag('RSA-2048-SHA3-256-SIG-VRF',public_key_sender_rsa,plaintext,nonce_hmac,tag3)
end=get_time.time()
print('Execution time for RSA-2048-SHA3-256-SIG-VRF ',(end-start)*1000)
#print('Tag length=',len(tag3))
#rint('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")


#Time diffrence calculation for ECDSA-256-SHA3-256-SIG-GEN
start = get_time.time()
tag4=obj.generate_auth_tag('ECDSA-256-SHA3-256-SIG-GEN',private_key_sender_ecc,plaintext,nonce_hmac)
end=get_time.time()
print('Execution time for RSA-2048-SHA3-256-SIG-GEN ',(end-start)*1000)
print('Tag length=',len(tag4))
print('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")



#Time diffrence calculation for ECDSA-256-SHA3-256-SIG-VRF
start = get_time.time()
obj.verify_auth_tag('ECDSA-256-SHA3-256-SIG-VRF',private_key_sender_ecc,plaintext,nonce_hmac,tag4)
end=get_time.time()
print('Execution time for RSA-2048-SHA3-256-SIG-GEN ',(end-start)*1000)
#print('Tag length=',len(tag3))
#print('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")

#Time diffrence calculation for AES-128-GCM-GEN
start = get_time.time()
ciphertext,auth_tag=obj.encrypt_generate_auth('AES-128-GCM-GEN', symmetric_key, symmetric_key, plaintext, nonce_aes_gcm)
end=get_time.time()
print('Execution time for RSA-2048-SHA3-256-SIG-GEN ',(end-start)*1000)
print('Tag length=',len(tag3))
print('CipherText length=',len(ciphertext))
print('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")

#Time diffrence calculation for AES-128-GCM-GEN
start = get_time.time()
ciphertext,auth_tag=obj.encrypt_generate_auth('AES-128-GCM-GEN', symmetric_key, symmetric_key, plaintext, nonce_aes_gcm)
end=get_time.time()
print('Execution time for RSA-2048-SHA3-256-SIG-GEN ',(end-start)*1000)
print('Tag length=',len(auth_tag))
print('CipherText length=',len(ciphertext))
print('Plaintext length=',len(plaintext))

print("\n\n-----------------------------------------------------------------------\n\n")

#Time diffrence calculation for AES-128-GCM-VRF
start = get_time.time()
plaintext,auth_tag_valid=obj.decrypt_verify_auth('AES-128-GCM-VRF', symmetric_key, symmetric_key, ciphertext, nonce_aes_gcm, auth_tag)
end=get_time.time()
print('Execution time for RSA-2048-SHA3-256-SIG-GEN ',(end-start)*1000)
#print('Tag length=',len(auth_tag_valid))
print('CipherText length=',len(ciphertext))
print('Plaintext length=',len(plaintext))