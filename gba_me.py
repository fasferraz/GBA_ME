import http.client
import ssl
from optparse import OptionParser
import serial
import base64
import json
from binascii import hexlify, unhexlify
import hashlib
import time
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
import struct

MCC = '268'
MNC = '006'
NAF_HOST = 'xcap.ims.mnc' + MNC + '.mcc' + MCC + '.pub.3gppnetwork.org'
BSF_HOST = 'bsf.mnc' + MNC + '.mcc' + MCC + '.pub.3gppnetwork.org'

KEYLOG_PATH = '/home/fabricio/ssl-keys.log' 

DEFAULT_IMSI = "268064901000504"
DEFAULT_MSISDN = "351964900562"
DEFAULT_IMEI = "1234567890123456"

tls_cipher_suite = {}
cipher_openssl_name = {}


def get_key(val): 
    for key, value in cipher_openssl_name.items(): 
        if val == value:          
            return key 
  
    return None

def initialize_tls_cipher_suite():

    #https://testssl.sh/openssl-iana.mapping.html

    cipher_openssl_name['DHE-RSA-CHACHA20-POLY1305']='TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
    cipher_openssl_name['RSA-PSK-AES256-GCM-SHA384']='TLS_RSA_PSK_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['DHE-PSK-AES256-GCM-SHA384']='TLS_DHE_PSK_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['PSK-AES256-GCM-SHA384']='TLS_PSK_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['RSA-PSK-AES128-GCM-SHA256']='TLS_RSA_PSK_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['DHE-PSK-AES128-GCM-SHA256']='TLS_DHE_PSK_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['PSK-AES128-GCM-SHA256']='TLS_PSK_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['ECDHE-PSK-AES256-CBC-SHA384']='TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384'
    cipher_openssl_name['ECDHE-PSK-AES256-CBC-SHA']='TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['SRP-RSA-AES-256-CBC-SHA']='TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['SRP-AES-256-CBC-SHA']='TLS_SRP_SHA_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['RSA-PSK-AES256-CBC-SHA384']='TLS_RSA_PSK_WITH_AES_256_CBC_SHA384'
    cipher_openssl_name['DHE-PSK-AES256-CBC-SHA384']='TLS_DHE_PSK_WITH_AES_256_CBC_SHA384'
    cipher_openssl_name['RSA-PSK-AES256-CBC-SHA']='TLS_RSA_PSK_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['DHE-PSK-AES256-CBC-SHA']='TLS_DHE_PSK_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['PSK-AES256-CBC-SHA384']='TLS_PSK_WITH_AES_256_CBC_SHA384'
    cipher_openssl_name['PSK-AES256-CBC-SHA']='TLS_PSK_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['ECDHE-PSK-AES128-CBC-SHA256']='TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['ECDHE-PSK-AES128-CBC-SHA']='TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['SRP-RSA-AES-128-CBC-SHA']='TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['SRP-AES-128-CBC-SHA']='TLS_SRP_SHA_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['RSA-PSK-AES128-CBC-SHA256']='TLS_RSA_PSK_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['DHE-PSK-AES128-CBC-SHA256']='TLS_DHE_PSK_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['RSA-PSK-AES128-CBC-SHA']='TLS_RSA_PSK_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['DHE-PSK-AES128-CBC-SHA']='TLS_DHE_PSK_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['PSK-AES128-CBC-SHA256']='TLS_PSK_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['PSK-AES128-CBC-SHA']='TLS_PSK_WITH_AES_128_CBC_SHA'

    #from https://www.openssl.org/docs/man1.1.1/man1/ciphers.html
    cipher_openssl_name['NULL-MD5']='SSL_RSA_WITH_NULL_MD5'
    cipher_openssl_name['NULL-SHA']='SSL_RSA_WITH_NULL_SHA'
    cipher_openssl_name['RC4-MD5']='SSL_RSA_WITH_RC4_128_MD5'
    cipher_openssl_name['RC4-SHA']='SSL_RSA_WITH_RC4_128_SHA'
    cipher_openssl_name['IDEA-CBC-SHA']='SSL_RSA_WITH_IDEA_CBC_SHA'
    cipher_openssl_name['DES-CBC3-SHA']='SSL_RSA_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['DH-DSS-DES-CBC3-SHA']='SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['DH-RSA-DES-CBC3-SHA']='SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['DHE-DSS-DES-CBC3-SHA']='SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['DHE-RSA-DES-CBC3-SHA']='SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['ADH-RC4-MD5']='SSL_DH_anon_WITH_RC4_128_MD5'
    cipher_openssl_name['ADH-DES-CBC3-SHA']='SSL_DH_anon_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['NULL-MD5']='TLS_RSA_WITH_NULL_MD5'
    cipher_openssl_name['NULL-SHA']='TLS_RSA_WITH_NULL_SHA'
    cipher_openssl_name['RC4-MD5']='TLS_RSA_WITH_RC4_128_MD5'
    cipher_openssl_name['RC4-SHA']='TLS_RSA_WITH_RC4_128_SHA'
    cipher_openssl_name['IDEA-CBC-SHA']='TLS_RSA_WITH_IDEA_CBC_SHA'
    cipher_openssl_name['DES-CBC3-SHA']='TLS_RSA_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['DHE-DSS-DES-CBC3-SHA']='TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['DHE-RSA-DES-CBC3-SHA']='TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['ADH-RC4-MD5']='TLS_DH_anon_WITH_RC4_128_MD5'
    cipher_openssl_name['ADH-DES-CBC3-SHA']='TLS_DH_anon_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['AES128-SHA']='TLS_RSA_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['AES256-SHA']='TLS_RSA_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['DH-DSS-AES128-SHA']='TLS_DH_DSS_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['DH-DSS-AES256-SHA']='TLS_DH_DSS_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['DH-RSA-AES128-SHA']='TLS_DH_RSA_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['DH-RSA-AES256-SHA']='TLS_DH_RSA_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['DHE-DSS-AES128-SHA']='TLS_DHE_DSS_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['DHE-DSS-AES256-SHA']='TLS_DHE_DSS_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['DHE-RSA-AES128-SHA']='TLS_DHE_RSA_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['DHE-RSA-AES256-SHA']='TLS_DHE_RSA_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['ADH-AES128-SHA']='TLS_DH_anon_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['ADH-AES256-SHA']='TLS_DH_anon_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['CAMELLIA128-SHA']='TLS_RSA_WITH_CAMELLIA_128_CBC_SHA'
    cipher_openssl_name['CAMELLIA256-SHA']='TLS_RSA_WITH_CAMELLIA_256_CBC_SHA'
    cipher_openssl_name['DH-DSS-CAMELLIA128-SHA']='TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA'
    cipher_openssl_name['DH-DSS-CAMELLIA256-SHA']='TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA'
    cipher_openssl_name['DH-RSA-CAMELLIA128-SHA']='TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA'
    cipher_openssl_name['DH-RSA-CAMELLIA256-SHA']='TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA'
    cipher_openssl_name['DHE-DSS-CAMELLIA128-SHA']='TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA'
    cipher_openssl_name['DHE-DSS-CAMELLIA256-SHA']='TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA'
    cipher_openssl_name['DHE-RSA-CAMELLIA128-SHA']='TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA'
    cipher_openssl_name['DHE-RSA-CAMELLIA256-SHA']='TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA'
    cipher_openssl_name['ADH-CAMELLIA128-SHA']='TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA'
    cipher_openssl_name['ADH-CAMELLIA256-SHA']='TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA'
    cipher_openssl_name['SEED-SHA']='TLS_RSA_WITH_SEED_CBC_SHA'
    cipher_openssl_name['DH-DSS-SEED-SHA']='TLS_DH_DSS_WITH_SEED_CBC_SHA'
    cipher_openssl_name['DH-RSA-SEED-SHA']='TLS_DH_RSA_WITH_SEED_CBC_SHA'
    cipher_openssl_name['DHE-DSS-SEED-SHA']='TLS_DHE_DSS_WITH_SEED_CBC_SHA'
    cipher_openssl_name['DHE-RSA-SEED-SHA']='TLS_DHE_RSA_WITH_SEED_CBC_SHA'
    cipher_openssl_name['ADH-SEED-SHA']='TLS_DH_anon_WITH_SEED_CBC_SHA'
    cipher_openssl_name['GOST94-GOST89-GOST89']='TLS_GOSTR341094_WITH_28147_CNT_IMIT'
    cipher_openssl_name['GOST2001-GOST89-GOST89']='TLS_GOSTR341001_WITH_28147_CNT_IMIT'
    cipher_openssl_name['GOST94-NULL-GOST94']='TLS_GOSTR341094_WITH_NULL_GOSTR3411'
    cipher_openssl_name['GOST2001-NULL-GOST94']='TLS_GOSTR341001_WITH_NULL_GOSTR3411'
    cipher_openssl_name['DHE-DSS-RC4-SHA']='TLS_DHE_DSS_WITH_RC4_128_SHA'
    cipher_openssl_name['ECDHE-RSA-NULL-SHA']='TLS_ECDHE_RSA_WITH_NULL_SHA'
    cipher_openssl_name['ECDHE-RSA-RC4-SHA']='TLS_ECDHE_RSA_WITH_RC4_128_SHA'
    cipher_openssl_name['ECDHE-RSA-DES-CBC3-SHA']='TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['ECDHE-RSA-AES128-SHA']='TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['ECDHE-RSA-AES256-SHA']='TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['ECDHE-ECDSA-NULL-SHA']='TLS_ECDHE_ECDSA_WITH_NULL_SHA'
    cipher_openssl_name['ECDHE-ECDSA-RC4-SHA']='TLS_ECDHE_ECDSA_WITH_RC4_128_SHA'
    cipher_openssl_name['ECDHE-ECDSA-DES-CBC3-SHA']='TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['ECDHE-ECDSA-AES128-SHA']='TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['ECDHE-ECDSA-AES256-SHA']='TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['AECDH-NULL-SHA']='TLS_ECDH_anon_WITH_NULL_SHA'
    cipher_openssl_name['AECDH-RC4-SHA']='TLS_ECDH_anon_WITH_RC4_128_SHA'
    cipher_openssl_name['AECDH-DES-CBC3-SHA']='TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['AECDH-AES128-SHA']='TLS_ECDH_anon_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['AECDH-AES256-SHA']='TLS_ECDH_anon_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['NULL-SHA256']='TLS_RSA_WITH_NULL_SHA256'
    cipher_openssl_name['AES128-SHA256']='TLS_RSA_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['AES256-SHA256']='TLS_RSA_WITH_AES_256_CBC_SHA256'
    cipher_openssl_name['AES128-GCM-SHA256']='TLS_RSA_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['AES256-GCM-SHA384']='TLS_RSA_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['DH-RSA-AES128-SHA256']='TLS_DH_RSA_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['DH-RSA-AES256-SHA256']='TLS_DH_RSA_WITH_AES_256_CBC_SHA256'
    cipher_openssl_name['DH-RSA-AES128-GCM-SHA256']='TLS_DH_RSA_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['DH-RSA-AES256-GCM-SHA384']='TLS_DH_RSA_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['DH-DSS-AES128-SHA256']='TLS_DH_DSS_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['DH-DSS-AES256-SHA256']='TLS_DH_DSS_WITH_AES_256_CBC_SHA256'
    cipher_openssl_name['DH-DSS-AES128-GCM-SHA256']='TLS_DH_DSS_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['DH-DSS-AES256-GCM-SHA384']='TLS_DH_DSS_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['DHE-RSA-AES128-SHA256']='TLS_DHE_RSA_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['DHE-RSA-AES256-SHA256']='TLS_DHE_RSA_WITH_AES_256_CBC_SHA256'
    cipher_openssl_name['DHE-RSA-AES128-GCM-SHA256']='TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['DHE-RSA-AES256-GCM-SHA384']='TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['DHE-DSS-AES128-SHA256']='TLS_DHE_DSS_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['DHE-DSS-AES256-SHA256']='TLS_DHE_DSS_WITH_AES_256_CBC_SHA256'
    cipher_openssl_name['DHE-DSS-AES128-GCM-SHA256']='TLS_DHE_DSS_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['DHE-DSS-AES256-GCM-SHA384']='TLS_DHE_DSS_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['ECDHE-RSA-AES128-SHA256']='TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['ECDHE-RSA-AES256-SHA384']='TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'
    cipher_openssl_name['ECDHE-RSA-AES128-GCM-SHA256']='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['ECDHE-RSA-AES256-GCM-SHA384']='TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['ECDHE-ECDSA-AES128-SHA256']='TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['ECDHE-ECDSA-AES256-SHA384']='TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'
    cipher_openssl_name['ECDHE-ECDSA-AES128-GCM-SHA256']='TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['ECDHE-ECDSA-AES256-GCM-SHA384']='TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['ADH-AES128-SHA256']='TLS_DH_anon_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['ADH-AES256-SHA256']='TLS_DH_anon_WITH_AES_256_CBC_SHA256'
    cipher_openssl_name['ADH-AES128-GCM-SHA256']='TLS_DH_anon_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['ADH-AES256-GCM-SHA384']='TLS_DH_anon_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['AES128-CCM']='RSA_WITH_AES_128_CCM'
    cipher_openssl_name['AES256-CCM']='RSA_WITH_AES_256_CCM'
    cipher_openssl_name['DHE-RSA-AES128-CCM']='DHE_RSA_WITH_AES_128_CCM'
    cipher_openssl_name['DHE-RSA-AES256-CCM']='DHE_RSA_WITH_AES_256_CCM'
    cipher_openssl_name['AES128-CCM8']='RSA_WITH_AES_128_CCM_8'
    cipher_openssl_name['AES256-CCM8']='RSA_WITH_AES_256_CCM_8'
    cipher_openssl_name['DHE-RSA-AES128-CCM8']='DHE_RSA_WITH_AES_128_CCM_8'
    cipher_openssl_name['DHE-RSA-AES256-CCM8']='DHE_RSA_WITH_AES_256_CCM_8'
    cipher_openssl_name['ECDHE-ECDSA-AES128-CCM']='ECDHE_ECDSA_WITH_AES_128_CCM'
    cipher_openssl_name['ECDHE-ECDSA-AES256-CCM']='ECDHE_ECDSA_WITH_AES_256_CCM'
    cipher_openssl_name['ECDHE-ECDSA-AES128-CCM8']='ECDHE_ECDSA_WITH_AES_128_CCM_8'
    cipher_openssl_name['ECDHE-ECDSA-AES256-CCM8']='ECDHE_ECDSA_WITH_AES_256_CCM_8'
    cipher_openssl_name['ARIA128-GCM-SHA256']='TLS_RSA_WITH_ARIA_128_GCM_SHA256'
    cipher_openssl_name['ARIA256-GCM-SHA384']='TLS_RSA_WITH_ARIA_256_GCM_SHA384'
    cipher_openssl_name['DHE-RSA-ARIA128-GCM-SHA256']='TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256'
    cipher_openssl_name['DHE-RSA-ARIA256-GCM-SHA384']='TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384'
    cipher_openssl_name['DHE-DSS-ARIA128-GCM-SHA256']='TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256'
    cipher_openssl_name['DHE-DSS-ARIA256-GCM-SHA384']='TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384'
    cipher_openssl_name['ECDHE-ECDSA-ARIA128-GCM-SHA256']='TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256'
    cipher_openssl_name['ECDHE-ECDSA-ARIA256-GCM-SHA384']='TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384'
    cipher_openssl_name['ECDHE-ARIA128-GCM-SHA256']='TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256'
    cipher_openssl_name['ECDHE-ARIA256-GCM-SHA384']='TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384'
    cipher_openssl_name['PSK-ARIA128-GCM-SHA256']='TLS_PSK_WITH_ARIA_128_GCM_SHA256'
    cipher_openssl_name['PSK-ARIA256-GCM-SHA384']='TLS_PSK_WITH_ARIA_256_GCM_SHA384'
    cipher_openssl_name['DHE-PSK-ARIA128-GCM-SHA256']='TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256'
    cipher_openssl_name['DHE-PSK-ARIA256-GCM-SHA384']='TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384'
    cipher_openssl_name['RSA-PSK-ARIA128-GCM-SHA256']='TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256'
    cipher_openssl_name['RSA-PSK-ARIA256-GCM-SHA384']='TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384'
    cipher_openssl_name['ECDHE-ECDSA-CAMELLIA128-SHA256']='TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'
    cipher_openssl_name['ECDHE-ECDSA-CAMELLIA256-SHA384']='TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'
    cipher_openssl_name['ECDHE-RSA-CAMELLIA128-SHA256']='TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256'
    cipher_openssl_name['ECDHE-RSA-CAMELLIA256-SHA384']='TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384'
    cipher_openssl_name['PSK-NULL-SHA']='PSK_WITH_NULL_SHA'
    cipher_openssl_name['DHE-PSK-NULL-SHA']='DHE_PSK_WITH_NULL_SHA'
    cipher_openssl_name['RSA-PSK-NULL-SHA']='RSA_PSK_WITH_NULL_SHA'
    cipher_openssl_name['PSK-RC4-SHA']='PSK_WITH_RC4_128_SHA'
    cipher_openssl_name['PSK-3DES-EDE-CBC-SHA']='PSK_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['PSK-AES128-CBC-SHA']='PSK_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['PSK-AES256-CBC-SHA']='PSK_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['DHE-PSK-RC4-SHA']='DHE_PSK_WITH_RC4_128_SHA'
    cipher_openssl_name['DHE-PSK-3DES-EDE-CBC-SHA']='DHE_PSK_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['DHE-PSK-AES128-CBC-SHA']='DHE_PSK_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['DHE-PSK-AES256-CBC-SHA']='DHE_PSK_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['RSA-PSK-RC4-SHA']='RSA_PSK_WITH_RC4_128_SHA'
    cipher_openssl_name['RSA-PSK-3DES-EDE-CBC-SHA']='RSA_PSK_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['RSA-PSK-AES128-CBC-SHA']='RSA_PSK_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['RSA-PSK-AES256-CBC-SHA']='RSA_PSK_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['PSK-AES128-GCM-SHA256']='PSK_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['PSK-AES256-GCM-SHA384']='PSK_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['DHE-PSK-AES128-GCM-SHA256']='DHE_PSK_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['DHE-PSK-AES256-GCM-SHA384']='DHE_PSK_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['RSA-PSK-AES128-GCM-SHA256']='RSA_PSK_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['RSA-PSK-AES256-GCM-SHA384']='RSA_PSK_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['PSK-AES128-CBC-SHA256']='PSK_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['PSK-AES256-CBC-SHA384']='PSK_WITH_AES_256_CBC_SHA384'
    cipher_openssl_name['PSK-NULL-SHA256']='PSK_WITH_NULL_SHA256'
    cipher_openssl_name['PSK-NULL-SHA384']='PSK_WITH_NULL_SHA384'
    cipher_openssl_name['DHE-PSK-AES128-CBC-SHA256']='DHE_PSK_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['DHE-PSK-AES256-CBC-SHA384']='DHE_PSK_WITH_AES_256_CBC_SHA384'
    cipher_openssl_name['DHE-PSK-NULL-SHA256']='DHE_PSK_WITH_NULL_SHA256'
    cipher_openssl_name['DHE-PSK-NULL-SHA384']='DHE_PSK_WITH_NULL_SHA384'
    cipher_openssl_name['RSA-PSK-AES128-CBC-SHA256']='RSA_PSK_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['RSA-PSK-AES256-CBC-SHA384']='RSA_PSK_WITH_AES_256_CBC_SHA384'
    cipher_openssl_name['RSA-PSK-NULL-SHA256']='RSA_PSK_WITH_NULL_SHA256'
    cipher_openssl_name['RSA-PSK-NULL-SHA384']='RSA_PSK_WITH_NULL_SHA384'
    cipher_openssl_name['PSK-AES128-GCM-SHA256']='PSK_WITH_AES_128_GCM_SHA256'
    cipher_openssl_name['PSK-AES256-GCM-SHA384']='PSK_WITH_AES_256_GCM_SHA384'
    cipher_openssl_name['ECDHE-PSK-RC4-SHA']='ECDHE_PSK_WITH_RC4_128_SHA'
    cipher_openssl_name['ECDHE-PSK-3DES-EDE-CBC-SHA']='ECDHE_PSK_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['ECDHE-PSK-AES128-CBC-SHA']='ECDHE_PSK_WITH_AES_128_CBC_SHA'
    cipher_openssl_name['ECDHE-PSK-AES256-CBC-SHA']='ECDHE_PSK_WITH_AES_256_CBC_SHA'
    cipher_openssl_name['ECDHE-PSK-AES128-CBC-SHA256']='ECDHE_PSK_WITH_AES_128_CBC_SHA256'
    cipher_openssl_name['ECDHE-PSK-AES256-CBC-SHA384']='ECDHE_PSK_WITH_AES_256_CBC_SHA384'
    cipher_openssl_name['ECDHE-PSK-NULL-SHA']='ECDHE_PSK_WITH_NULL_SHA'
    cipher_openssl_name['ECDHE-PSK-NULL-SHA256']='ECDHE_PSK_WITH_NULL_SHA256'
    cipher_openssl_name['ECDHE-PSK-NULL-SHA384']='ECDHE_PSK_WITH_NULL_SHA384'
    cipher_openssl_name['PSK-CAMELLIA128-SHA256']='PSK_WITH_CAMELLIA_128_CBC_SHA256'
    cipher_openssl_name['PSK-CAMELLIA256-SHA384']='PSK_WITH_CAMELLIA_256_CBC_SHA384'
    cipher_openssl_name['DHE-PSK-CAMELLIA128-SHA256']='DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'
    cipher_openssl_name['DHE-PSK-CAMELLIA256-SHA384']='DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'
    cipher_openssl_name['RSA-PSK-CAMELLIA128-SHA256']='RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256'
    cipher_openssl_name['RSA-PSK-CAMELLIA256-SHA384']='RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384'
    cipher_openssl_name['ECDHE-PSK-CAMELLIA128-SHA256']='ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'
    cipher_openssl_name['ECDHE-PSK-CAMELLIA256-SHA384']='ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'
    cipher_openssl_name['PSK-AES128-CCM']='PSK_WITH_AES_128_CCM'
    cipher_openssl_name['PSK-AES256-CCM']='PSK_WITH_AES_256_CCM'
    cipher_openssl_name['DHE-PSK-AES128-CCM']='DHE_PSK_WITH_AES_128_CCM'
    cipher_openssl_name['DHE-PSK-AES256-CCM']='DHE_PSK_WITH_AES_256_CCM'
    cipher_openssl_name['PSK-AES128-CCM8']='PSK_WITH_AES_128_CCM_8'
    cipher_openssl_name['PSK-AES256-CCM8']='PSK_WITH_AES_256_CCM_8'
    cipher_openssl_name['DHE-PSK-AES128-CCM8']='DHE_PSK_WITH_AES_128_CCM_8'
    cipher_openssl_name['DHE-PSK-AES256-CCM8']='DHE_PSK_WITH_AES_256_CCM_8'
    cipher_openssl_name['ECDHE-RSA-CHACHA20-POLY1305']='TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
    cipher_openssl_name['ECDHE-ECDSA-CHACHA20-POLY1305']='TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'
    cipher_openssl_name['DHE-RSA-CHACHA20-POLY1305']='TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
    cipher_openssl_name['PSK-CHACHA20-POLY1305']='TLS_PSK_WITH_CHACHA20_POLY1305_SHA256'
    cipher_openssl_name['ECDHE-PSK-CHACHA20-POLY1305']='TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256'
    cipher_openssl_name['DHE-PSK-CHACHA20-POLY1305']='TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256'
    cipher_openssl_name['RSA-PSK-CHACHA20-POLY1305']='TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256'
    cipher_openssl_name['TLS_AES_128_GCM_SHA256']='TLS_AES_128_GCM_SHA256'
    cipher_openssl_name['TLS_AES_256_GCM_SHA384']='TLS_AES_256_GCM_SHA384'
    cipher_openssl_name['TLS_CHACHA20_POLY1305_SHA256']='TLS_CHACHA20_POLY1305_SHA256'
    cipher_openssl_name['TLS_AES_128_CCM_SHA256']='TLS_AES_128_CCM_SHA256'
    cipher_openssl_name['TLS_AES_128_CCM_8_SHA256']='TLS_AES_128_CCM_8_SHA256'
    cipher_openssl_name['EDH-RSA-DES-CBC3-SHA']='SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA'
    cipher_openssl_name['EDH-DSS-DES-CBC3-SHA']='SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA'


    #from https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    tls_cipher_suite['TLS_NULL_WITH_NULL_NULL'] = '0000'
    tls_cipher_suite['TLS_RSA_WITH_NULL_MD5'] = '0001'
    tls_cipher_suite['TLS_RSA_WITH_NULL_SHA'] = '0002'
    tls_cipher_suite['TLS_RSA_EXPORT_WITH_RC4_40_MD5'] = '0003'
    tls_cipher_suite['TLS_RSA_WITH_RC4_128_MD5'] = '0004'
    tls_cipher_suite['TLS_RSA_WITH_RC4_128_SHA'] = '0005'
    tls_cipher_suite['TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5'] = '0006'
    tls_cipher_suite['TLS_RSA_WITH_IDEA_CBC_SHA'] = '0007'
    tls_cipher_suite['TLS_RSA_EXPORT_WITH_DES40_CBC_SHA'] = '0008'
    tls_cipher_suite['TLS_RSA_WITH_DES_CBC_SHA'] = '0009'
    tls_cipher_suite['TLS_RSA_WITH_3DES_EDE_CBC_SHA'] = '000A'
    tls_cipher_suite['TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA'] = '000B'
    tls_cipher_suite['TLS_DH_DSS_WITH_DES_CBC_SHA'] = '000C'
    tls_cipher_suite['TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA'] = '000D'
    tls_cipher_suite['TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA'] = '000E'
    tls_cipher_suite['TLS_DH_RSA_WITH_DES_CBC_SHA'] = '000F'
    tls_cipher_suite['TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA'] = '0010'
    tls_cipher_suite['TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA'] = '0011'
    tls_cipher_suite['TLS_DHE_DSS_WITH_DES_CBC_SHA'] = '0012'
    tls_cipher_suite['TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'] = '0013'
    tls_cipher_suite['TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA'] = '0014'
    tls_cipher_suite['TLS_DHE_RSA_WITH_DES_CBC_SHA'] = '0015'
    tls_cipher_suite['TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA'] = '0016'
    tls_cipher_suite['TLS_DH_anon_EXPORT_WITH_RC4_40_MD5'] = '0017'
    tls_cipher_suite['TLS_DH_anon_WITH_RC4_128_MD5'] = '0018'
    tls_cipher_suite['TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA'] = '0019'
    tls_cipher_suite['TLS_DH_anon_WITH_DES_CBC_SHA'] = '001A'
    tls_cipher_suite['TLS_DH_anon_WITH_3DES_EDE_CBC_SHA'] = '001B'
    tls_cipher_suite['TLS_KRB5_WITH_DES_CBC_SHA'] = '001E'
    tls_cipher_suite['TLS_KRB5_WITH_3DES_EDE_CBC_SHA'] = '001F'
    tls_cipher_suite['TLS_KRB5_WITH_RC4_128_SHA'] = '0020'
    tls_cipher_suite['TLS_KRB5_WITH_IDEA_CBC_SHA'] = '0021'
    tls_cipher_suite['TLS_KRB5_WITH_DES_CBC_MD5'] = '0022'
    tls_cipher_suite['TLS_KRB5_WITH_3DES_EDE_CBC_MD5'] = '0023'
    tls_cipher_suite['TLS_KRB5_WITH_RC4_128_MD5'] = '0024'
    tls_cipher_suite['TLS_KRB5_WITH_IDEA_CBC_MD5'] = '0025'
    tls_cipher_suite['TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA'] = '0026'
    tls_cipher_suite['TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA'] = '0027'
    tls_cipher_suite['TLS_KRB5_EXPORT_WITH_RC4_40_SHA'] = '0028'
    tls_cipher_suite['TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5'] = '0029'
    tls_cipher_suite['TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5'] = '002A'
    tls_cipher_suite['TLS_KRB5_EXPORT_WITH_RC4_40_MD5'] = '002B'
    tls_cipher_suite['TLS_PSK_WITH_NULL_SHA'] = '002C'
    tls_cipher_suite['TLS_DHE_PSK_WITH_NULL_SHA'] = '002D'
    tls_cipher_suite['TLS_RSA_PSK_WITH_NULL_SHA'] = '002E'
    tls_cipher_suite['TLS_RSA_WITH_AES_128_CBC_SHA'] = '002F'
    tls_cipher_suite['TLS_DH_DSS_WITH_AES_128_CBC_SHA'] = '0030'
    tls_cipher_suite['TLS_DH_RSA_WITH_AES_128_CBC_SHA'] = '0031'
    tls_cipher_suite['TLS_DHE_DSS_WITH_AES_128_CBC_SHA'] = '0032'
    tls_cipher_suite['TLS_DHE_RSA_WITH_AES_128_CBC_SHA'] = '0033'
    tls_cipher_suite['TLS_DH_anon_WITH_AES_128_CBC_SHA'] = '0034'
    tls_cipher_suite['TLS_RSA_WITH_AES_256_CBC_SHA'] = '0035'
    tls_cipher_suite['TLS_DH_DSS_WITH_AES_256_CBC_SHA'] = '0036'
    tls_cipher_suite['TLS_DH_RSA_WITH_AES_256_CBC_SHA'] = '0037'
    tls_cipher_suite['TLS_DHE_DSS_WITH_AES_256_CBC_SHA'] = '0038'
    tls_cipher_suite['TLS_DHE_RSA_WITH_AES_256_CBC_SHA'] = '0039'
    tls_cipher_suite['TLS_DH_anon_WITH_AES_256_CBC_SHA'] = '003A'
    tls_cipher_suite['TLS_RSA_WITH_NULL_SHA256'] = '003B'
    tls_cipher_suite['TLS_RSA_WITH_AES_128_CBC_SHA256'] = '003C'
    tls_cipher_suite['TLS_RSA_WITH_AES_256_CBC_SHA256'] = '003D'
    tls_cipher_suite['TLS_DH_DSS_WITH_AES_128_CBC_SHA256'] = '003E'
    tls_cipher_suite['TLS_DH_RSA_WITH_AES_128_CBC_SHA256'] = '003F'
    tls_cipher_suite['TLS_DHE_DSS_WITH_AES_128_CBC_SHA256'] = '0040'
    tls_cipher_suite['TLS_RSA_WITH_CAMELLIA_128_CBC_SHA'] = '0041'
    tls_cipher_suite['TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA'] = '0042'
    tls_cipher_suite['TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA'] = '0043'
    tls_cipher_suite['TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA'] = '0044'
    tls_cipher_suite['TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA'] = '0045'
    tls_cipher_suite['TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA'] = '0046'
    tls_cipher_suite['TLS_DHE_RSA_WITH_AES_128_CBC_SHA256'] = '0067'
    tls_cipher_suite['TLS_DH_DSS_WITH_AES_256_CBC_SHA256'] = '0068'
    tls_cipher_suite['TLS_DH_RSA_WITH_AES_256_CBC_SHA256'] = '0069'
    tls_cipher_suite['TLS_DHE_DSS_WITH_AES_256_CBC_SHA256'] = '006A'
    tls_cipher_suite['TLS_DHE_RSA_WITH_AES_256_CBC_SHA256'] = '006B'
    tls_cipher_suite['TLS_DH_anon_WITH_AES_128_CBC_SHA256'] = '006C'
    tls_cipher_suite['TLS_DH_anon_WITH_AES_256_CBC_SHA256'] = '006D'
    tls_cipher_suite['TLS_RSA_WITH_CAMELLIA_256_CBC_SHA'] = '0084'
    tls_cipher_suite['TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA'] = '0085'
    tls_cipher_suite['TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA'] = '0086'
    tls_cipher_suite['TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA'] = '0087'
    tls_cipher_suite['TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA'] = '0088'
    tls_cipher_suite['TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA'] = '0089'
    tls_cipher_suite['TLS_PSK_WITH_RC4_128_SHA'] = '008A'
    tls_cipher_suite['TLS_PSK_WITH_3DES_EDE_CBC_SHA'] = '008B'
    tls_cipher_suite['TLS_PSK_WITH_AES_128_CBC_SHA'] = '008C'
    tls_cipher_suite['TLS_PSK_WITH_AES_256_CBC_SHA'] = '008D'
    tls_cipher_suite['TLS_DHE_PSK_WITH_RC4_128_SHA'] = '008E'
    tls_cipher_suite['TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA'] = '008F'
    tls_cipher_suite['TLS_DHE_PSK_WITH_AES_128_CBC_SHA'] = '0090'
    tls_cipher_suite['TLS_DHE_PSK_WITH_AES_256_CBC_SHA'] = '0091'
    tls_cipher_suite['TLS_RSA_PSK_WITH_RC4_128_SHA'] = '0092'
    tls_cipher_suite['TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA'] = '0093'
    tls_cipher_suite['TLS_RSA_PSK_WITH_AES_128_CBC_SHA'] = '0094'
    tls_cipher_suite['TLS_RSA_PSK_WITH_AES_256_CBC_SHA'] = '0095'
    tls_cipher_suite['TLS_RSA_WITH_SEED_CBC_SHA'] = '0096'
    tls_cipher_suite['TLS_DH_DSS_WITH_SEED_CBC_SHA'] = '0097'
    tls_cipher_suite['TLS_DH_RSA_WITH_SEED_CBC_SHA'] = '0098'
    tls_cipher_suite['TLS_DHE_DSS_WITH_SEED_CBC_SHA'] = '0099'
    tls_cipher_suite['TLS_DHE_RSA_WITH_SEED_CBC_SHA'] = '009A'
    tls_cipher_suite['TLS_DH_anon_WITH_SEED_CBC_SHA'] = '009B'
    tls_cipher_suite['TLS_RSA_WITH_AES_128_GCM_SHA256'] = '009C'
    tls_cipher_suite['TLS_RSA_WITH_AES_256_GCM_SHA384'] = '009D'
    tls_cipher_suite['TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'] = '009E'
    tls_cipher_suite['TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'] = '009F'
    tls_cipher_suite['TLS_DH_RSA_WITH_AES_128_GCM_SHA256'] = '00A0'
    tls_cipher_suite['TLS_DH_RSA_WITH_AES_256_GCM_SHA384'] = '00A1'
    tls_cipher_suite['TLS_DHE_DSS_WITH_AES_128_GCM_SHA256'] = '00A2'
    tls_cipher_suite['TLS_DHE_DSS_WITH_AES_256_GCM_SHA384'] = '00A3'
    tls_cipher_suite['TLS_DH_DSS_WITH_AES_128_GCM_SHA256'] = '00A4'
    tls_cipher_suite['TLS_DH_DSS_WITH_AES_256_GCM_SHA384'] = '00A5'
    tls_cipher_suite['TLS_DH_anon_WITH_AES_128_GCM_SHA256'] = '00A6'
    tls_cipher_suite['TLS_DH_anon_WITH_AES_256_GCM_SHA384'] = '00A7'
    tls_cipher_suite['TLS_PSK_WITH_AES_128_GCM_SHA256'] = '00A8'
    tls_cipher_suite['TLS_PSK_WITH_AES_256_GCM_SHA384'] = '00A9'
    tls_cipher_suite['TLS_DHE_PSK_WITH_AES_128_GCM_SHA256'] = '00AA'
    tls_cipher_suite['TLS_DHE_PSK_WITH_AES_256_GCM_SHA384'] = '00AB'
    tls_cipher_suite['TLS_RSA_PSK_WITH_AES_128_GCM_SHA256'] = '00AC'
    tls_cipher_suite['TLS_RSA_PSK_WITH_AES_256_GCM_SHA384'] = '00AD'
    tls_cipher_suite['TLS_PSK_WITH_AES_128_CBC_SHA256'] = '00AE'
    tls_cipher_suite['TLS_PSK_WITH_AES_256_CBC_SHA384'] = '00AF'
    tls_cipher_suite['TLS_PSK_WITH_NULL_SHA256'] = '00B0'
    tls_cipher_suite['TLS_PSK_WITH_NULL_SHA384'] = '00B1'
    tls_cipher_suite['TLS_DHE_PSK_WITH_AES_128_CBC_SHA256'] = '00B2'
    tls_cipher_suite['TLS_DHE_PSK_WITH_AES_256_CBC_SHA384'] = '00B3'
    tls_cipher_suite['TLS_DHE_PSK_WITH_NULL_SHA256'] = '00B4'
    tls_cipher_suite['TLS_DHE_PSK_WITH_NULL_SHA384'] = '00B5'
    tls_cipher_suite['TLS_RSA_PSK_WITH_AES_128_CBC_SHA256'] = '00B6'
    tls_cipher_suite['TLS_RSA_PSK_WITH_AES_256_CBC_SHA384'] = '00B7'
    tls_cipher_suite['TLS_RSA_PSK_WITH_NULL_SHA256'] = '00B8'
    tls_cipher_suite['TLS_RSA_PSK_WITH_NULL_SHA384'] = '00B9'
    tls_cipher_suite['TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256'] = '00BA'
    tls_cipher_suite['TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256'] = '00BB'
    tls_cipher_suite['TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256'] = '00BC'
    tls_cipher_suite['TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256'] = '00BD'
    tls_cipher_suite['TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256'] = '00BE'
    tls_cipher_suite['TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256'] = '00BF'
    tls_cipher_suite['TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256'] = '00C0'
    tls_cipher_suite['TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256'] = '00C1'
    tls_cipher_suite['TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256'] = '00C2'
    tls_cipher_suite['TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256'] = '00C3'
    tls_cipher_suite['TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256'] = '00C4'
    tls_cipher_suite['TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256'] = '00C5'
    tls_cipher_suite['TLS_SM4_GCM_SM3'] = '00C6'
    tls_cipher_suite['TLS_SM4_CCM_SM3'] = '00C7'
    tls_cipher_suite['TLS_EMPTY_RENEGOTIATION_INFO_SCSV'] = '00FF'
    tls_cipher_suite['TLS_AES_128_GCM_SHA256'] = '1301'
    tls_cipher_suite['TLS_AES_256_GCM_SHA384'] = '1302'
    tls_cipher_suite['TLS_CHACHA20_POLY1305_SHA256'] = '1303'
    tls_cipher_suite['TLS_AES_128_CCM_SHA256'] = '1304'
    tls_cipher_suite['TLS_AES_128_CCM_8_SHA256'] = '1305'
    tls_cipher_suite['TLS_FALLBACK_SCSV'] = '5600'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_NULL_SHA'] = 'C001'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_RC4_128_SHA'] = 'C002'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA'] = 'C003'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA'] = 'C004'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA'] = 'C005'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_NULL_SHA'] = 'C006'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_RC4_128_SHA'] = 'C007'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA'] = 'C008'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'] = 'C009'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'] = 'C00A'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_NULL_SHA'] = 'C00B'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_RC4_128_SHA'] = 'C00C'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA'] = 'C00D'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_AES_128_CBC_SHA'] = 'C00E'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_AES_256_CBC_SHA'] = 'C00F'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_NULL_SHA'] = 'C010'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_RC4_128_SHA'] = 'C011'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA'] = 'C012'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'] = 'C013'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'] = 'C014'
    tls_cipher_suite['TLS_ECDH_anon_WITH_NULL_SHA'] = 'C015'
    tls_cipher_suite['TLS_ECDH_anon_WITH_RC4_128_SHA'] = 'C016'
    tls_cipher_suite['TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA'] = 'C017'
    tls_cipher_suite['TLS_ECDH_anon_WITH_AES_128_CBC_SHA'] = 'C018'
    tls_cipher_suite['TLS_ECDH_anon_WITH_AES_256_CBC_SHA'] = 'C019'
    tls_cipher_suite['TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA'] = 'C01A'
    tls_cipher_suite['TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA'] = 'C01B'
    tls_cipher_suite['TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA'] = 'C01C'
    tls_cipher_suite['TLS_SRP_SHA_WITH_AES_128_CBC_SHA'] = 'C01D'
    tls_cipher_suite['TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA'] = 'C01E'
    tls_cipher_suite['TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA'] = 'C01F'
    tls_cipher_suite['TLS_SRP_SHA_WITH_AES_256_CBC_SHA'] = 'C020'
    tls_cipher_suite['TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA'] = 'C021'
    tls_cipher_suite['TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA'] = 'C022'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'] = 'C023'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'] = 'C024'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256'] = 'C025'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384'] = 'C026'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'] = 'C027'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'] = 'C028'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256'] = 'C029'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384'] = 'C02A'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'] = 'C02B'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'] = 'C02C'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256'] = 'C02D'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384'] = 'C02E'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'] = 'C02F'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'] = 'C030'                    
    tls_cipher_suite['TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256'] = 'C031'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384'] = 'C032'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_RC4_128_SHA'] = 'C033'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA'] = 'C034'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA'] = 'C035'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA'] = 'C036'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256'] = 'C037'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384'] = 'C038'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_NULL_SHA'] = 'C039'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_NULL_SHA256'] = 'C03A'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_NULL_SHA384'] = 'C03B'
    tls_cipher_suite['TLS_RSA_WITH_ARIA_128_CBC_SHA256'] = 'C03C'
    tls_cipher_suite['TLS_RSA_WITH_ARIA_256_CBC_SHA384'] = 'C03D'
    tls_cipher_suite['TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256'] = 'C03E'
    tls_cipher_suite['TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384'] = 'C03F'
    tls_cipher_suite['TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256'] = 'C040'
    tls_cipher_suite['TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384'] = 'C041'
    tls_cipher_suite['TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256'] = 'C042'
    tls_cipher_suite['TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384'] = 'C043'
    tls_cipher_suite['TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256'] = 'C044'
    tls_cipher_suite['TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384'] = 'C045'
    tls_cipher_suite['TLS_DH_anon_WITH_ARIA_128_CBC_SHA256'] = 'C046'
    tls_cipher_suite['TLS_DH_anon_WITH_ARIA_256_CBC_SHA384'] = 'C047'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256'] = 'C048'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384'] = 'C049'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256'] = 'C04A'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384'] = 'C04B'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256'] = 'C04C'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384'] = 'C04D'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256'] = 'C04E'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384'] = 'C04F'
    tls_cipher_suite['TLS_RSA_WITH_ARIA_128_GCM_SHA256'] = 'C050'
    tls_cipher_suite['TLS_RSA_WITH_ARIA_256_GCM_SHA384'] = 'C051'
    tls_cipher_suite['TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256'] = 'C052'
    tls_cipher_suite['TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384'] = 'C053'
    tls_cipher_suite['TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256'] = 'C054'
    tls_cipher_suite['TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384'] = 'C055'
    tls_cipher_suite['TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256'] = 'C056'
    tls_cipher_suite['TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384'] = 'C057'
    tls_cipher_suite['TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256'] = 'C058'
    tls_cipher_suite['TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384'] = 'C059'
    tls_cipher_suite['TLS_DH_anon_WITH_ARIA_128_GCM_SHA256'] = 'C05A'
    tls_cipher_suite['TLS_DH_anon_WITH_ARIA_256_GCM_SHA384'] = 'C05B'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256'] = 'C05C'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384'] = 'C05D'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256'] = 'C05E'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384'] = 'C05F'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256'] = 'C060'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384'] = 'C061'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256'] = 'C062'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384'] = 'C063'
    tls_cipher_suite['TLS_PSK_WITH_ARIA_128_CBC_SHA256'] = 'C064'
    tls_cipher_suite['TLS_PSK_WITH_ARIA_256_CBC_SHA384'] = 'C065'
    tls_cipher_suite['TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256'] = 'C066'
    tls_cipher_suite['TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384'] = 'C067'
    tls_cipher_suite['TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256'] = 'C068'
    tls_cipher_suite['TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384'] = 'C069'
    tls_cipher_suite['TLS_PSK_WITH_ARIA_128_GCM_SHA256'] = 'C06A'
    tls_cipher_suite['TLS_PSK_WITH_ARIA_256_GCM_SHA384'] = 'C06B'
    tls_cipher_suite['TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256'] = 'C06C'
    tls_cipher_suite['TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384'] = 'C06D'
    tls_cipher_suite['TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256'] = 'C06E'
    tls_cipher_suite['TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384'] = 'C06F'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256'] = 'C070'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384'] = 'C071'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'] = 'C072'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'] = 'C073'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'] = 'C074'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'] = 'C075'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256'] = 'C076'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384'] = 'C077'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256'] = 'C078'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384'] = 'C079'
    tls_cipher_suite['TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256'] = 'C07A'
    tls_cipher_suite['TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384'] = 'C07B'
    tls_cipher_suite['TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256'] = 'C07C'
    tls_cipher_suite['TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384'] = 'C07D'
    tls_cipher_suite['TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256'] = 'C07E'
    tls_cipher_suite['TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384'] = 'C07F'
    tls_cipher_suite['TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256'] = 'C080'
    tls_cipher_suite['TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384'] = 'C081'
    tls_cipher_suite['TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256'] = 'C082'
    tls_cipher_suite['TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384'] = 'C083'
    tls_cipher_suite['TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256'] = 'C084'
    tls_cipher_suite['TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384'] = 'C085'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256'] = 'C086'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384'] = 'C087'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256'] = 'C088'
    tls_cipher_suite['TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384'] = 'C089'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256'] = 'C08A'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384'] = 'C08B'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256'] = 'C08C'
    tls_cipher_suite['TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384'] = 'C08D'
    tls_cipher_suite['TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256'] = 'C08E'
    tls_cipher_suite['TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384'] = 'C08F'
    tls_cipher_suite['TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256'] = 'C090'
    tls_cipher_suite['TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384'] = 'C091'
    tls_cipher_suite['TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256'] = 'C092'
    tls_cipher_suite['TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384'] = 'C093'
    tls_cipher_suite['TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256'] = 'C094'
    tls_cipher_suite['TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384'] = 'C095'
    tls_cipher_suite['TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'] = 'C096'
    tls_cipher_suite['TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'] = 'C097'
    tls_cipher_suite['TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256'] = 'C098'
    tls_cipher_suite['TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384'] = 'C099'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'] = 'C09A'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'] = 'C09B'
    tls_cipher_suite['TLS_RSA_WITH_AES_128_CCM'] = 'C09C'
    tls_cipher_suite['TLS_RSA_WITH_AES_256_CCM'] = 'C09D'
    tls_cipher_suite['TLS_DHE_RSA_WITH_AES_128_CCM'] = 'C09E'
    tls_cipher_suite['TLS_DHE_RSA_WITH_AES_256_CCM'] = 'C09F'
    tls_cipher_suite['TLS_RSA_WITH_AES_128_CCM_8'] = 'C0A0'
    tls_cipher_suite['TLS_RSA_WITH_AES_256_CCM_8'] = 'C0A1'
    tls_cipher_suite['TLS_DHE_RSA_WITH_AES_128_CCM_8'] = 'C0A2'
    tls_cipher_suite['TLS_DHE_RSA_WITH_AES_256_CCM_8'] = 'C0A3'
    tls_cipher_suite['TLS_PSK_WITH_AES_128_CCM'] = 'C0A4'
    tls_cipher_suite['TLS_PSK_WITH_AES_256_CCM'] = 'C0A5'
    tls_cipher_suite['TLS_DHE_PSK_WITH_AES_128_CCM'] = 'C0A6'
    tls_cipher_suite['TLS_DHE_PSK_WITH_AES_256_CCM'] = 'C0A7'
    tls_cipher_suite['TLS_PSK_WITH_AES_128_CCM_8'] = 'C0A8'
    tls_cipher_suite['TLS_PSK_WITH_AES_256_CCM_8'] = 'C0A9'
    tls_cipher_suite['TLS_PSK_DHE_WITH_AES_128_CCM_8'] = 'C0AA'
    tls_cipher_suite['TLS_PSK_DHE_WITH_AES_256_CCM_8'] = 'C0AB'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_AES_128_CCM'] = 'C0AC'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_AES_256_CCM'] = 'C0AD'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8'] = 'C0AE'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8'] = 'C0AF'
    tls_cipher_suite['TLS_ECCPWD_WITH_AES_128_GCM_SHA256'] = 'C0B0'
    tls_cipher_suite['TLS_ECCPWD_WITH_AES_256_GCM_SHA384'] = 'C0B1'
    tls_cipher_suite['TLS_ECCPWD_WITH_AES_128_CCM_SHA256'] = 'C0B2'
    tls_cipher_suite['TLS_ECCPWD_WITH_AES_256_CCM_SHA384'] = 'C0B3'
    tls_cipher_suite['TLS_SHA256_SHA256'] = 'C0B4'
    tls_cipher_suite['TLS_SHA384_SHA384'] = 'C0B5'
    tls_cipher_suite['TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC'] = 'C100'
    tls_cipher_suite['TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC'] = 'C101'
    tls_cipher_suite['TLS_GOSTR341112_256_WITH_28147_CNT_IMIT'] = 'C102'
    tls_cipher_suite['TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L'] = 'C103'
    tls_cipher_suite['TLS_GOSTR341112_256_WITH_MAGMA_MGM_L'] = 'C104'
    tls_cipher_suite['TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S'] = 'C105'
    tls_cipher_suite['TLS_GOSTR341112_256_WITH_MAGMA_MGM_S'] = 'C106'
    tls_cipher_suite['TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'] = 'CCA8'
    tls_cipher_suite['TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'] = 'CCA9'
    tls_cipher_suite['TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256'] = 'CCAA'
    tls_cipher_suite['TLS_PSK_WITH_CHACHA20_POLY1305_SHA256'] = 'CCAB'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256'] = 'CCAC'
    tls_cipher_suite['TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256'] = 'CCAD'
    tls_cipher_suite['TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256'] = 'CCAE'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256'] = 'D001'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384'] = 'D002'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256'] = 'D003'
    tls_cipher_suite['TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256'] = 'D005'



def get_res_ck_ik(serial_interface, rand, autn):
    res = None
    ck = None
    ik = None
        
    ser = serial.Serial(serial_interface,38400, timeout=0.5,xonxoff=True, rtscts=True, dsrdtr=True, exclusive =False)

    CLI = []
    CLI.append('AT+CRSM=178,12032,1,4,0\r\n')
    CLI.append('AT+CSIM=16,"00A40000023F0000"\r\n')
    CLI.append('AT+CSIM=16,"00A40000022F0000"\r\n')
    CLI.append('AT+CSIM=42,"00A4040010A0000000871002FFFFFFFF8903050001"\r\n')
    CLI.append('AT+CSIM=80,\"008800812210' + rand.upper() + '10' + autn.upper() + '00\"\r\n')

    a = time.time()
    for i in CLI:
        ser.write(i.encode())
        buffer = ''
    
        while "OK" not in buffer and "ERROR" not in buffer:
            buffer +=  ser.read().decode("utf-8")
        
            if time.time()-a > 0.5:
                ser.write(i.encode())
                a = time.time() + 1

    for i in buffer.split('"'):
        if len(i)==4:
            if i[0:2] == '61':
                len_result = i[-2:]
    
    LAST_CLI = 'AT+CSIM=10,"00C00000' + len_result + '\"\r\n'
    ser.write(LAST_CLI.encode())
    buffer = ''
    
    while "OK\r\n" not in buffer and "ERROR\r\n" not in buffer:
        buffer +=  ser.read().decode("utf-8")
        
    for result in buffer.split('"'):
        if len(result) > 10:
            res = result[4:20]
            ck = result[22:54]
            ik = result[56:88]
    
    ser.close()    
    return res, ck, ik

def parse_headers(text):
    return_dict = {}
    if text is not None:
        aux = text.split(',')
        for i in aux:
            pos = i.find('=')
            if i[pos+1] == '"':
                return_dict[i[0:pos].strip()] = i[pos+2:-1].strip()
            else:
                return_dict[i[0:pos].strip()] = i[pos+1:].strip()
    return return_dict
  
def get_response(username, realm, password, method, uri, nonce, nc, cnonce, qop, entity_body):

    h1 = hashlib.md5((username + ':' + realm + ':').encode()  + password).hexdigest()  
    heb = hashlib.md5(entity_body).hexdigest() 
    if qop == 'auth-int':
        h2 = hashlib.md5((method + ':' + uri + ':' + heb).encode()).hexdigest()
    else:
        h2 = hashlib.md5((method + ':' + uri).encode()).hexdigest() 
    kd = hashlib.md5((h1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + h2).encode()).hexdigest() 
    return kd


def int2hex(num):  #up to 255
    return hexlify(bytes([num])).decode('utf-8')

def str2hex(text):
    return hexlify(text.encode('utf-8')).decode('utf-8')
    
def get_Ks_NAF(ck, ik, rand, impi, naf, protocol_identifier):
    s = '016762612d6d650006' + rand + '0010' + str2hex(impi) + '00' + int2hex(len(impi)) + str2hex(naf) + protocol_identifier + '00' + int2hex(len(naf)+5)    
    message = unhexlify(s)
    key = unhexlify(ck + ik)
  
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    return h.digest()[-32:]


def get_TMPI(ck, ik, rand, impi, bsf):
    protocol_identifier = '0100000100' # TMPI According to Annex B.4
    
    s = '016762612d6d650006' + rand + '0010' + str2hex(impi) + '00' + int2hex(len(impi)) + str2hex(bsf) + protocol_identifier + '00' + int2hex(len(bsf)+5)
    message = unhexlify(s)
    key = unhexlify(ck + ik)
    
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    return base64.b64encode(h.digest()[0:24]).decode('utf-8') + '@tmpi.bsf.3gppnetwork.org '

  
def main():

    parser = OptionParser()    
    parser.add_option("-M", "--msisdn", dest="msisdn", default=DEFAULT_MSISDN, help="MSISDN")
    parser.add_option("-I", "--imsi", dest="imsi", default=DEFAULT_IMSI, help="IMSI (15 digits)")
    parser.add_option("-E", "--imei", dest="imei", default=DEFAULT_IMEI, help="IMEI-SV (16 digits)")    
    
    parser.add_option("-u", "--usb_device", dest="serial_interface", default= "/dev/ttyUSB2", help="usb tty (e.g /dev/ttyUSBx)")  
    parser.add_option("-S", "--https", dest="https",  action="store_true", default=False, help="use HTTPS. Default is HTTP") 
    parser.add_option("-T", "--tel", dest="tel",  action="store_true", default=False, help="use Tel URI instead of SIP URI in X-3GPP-Intended-Identity") 
    parser.add_option("-X", "--unverified_context", dest="check_https",  action="store_true", default=False, help="Check HTTPS Certificaton. Default is not check HTTPS") 
    parser.add_option("-C", "--cipher-suite", dest="cipher_suite",  default="All", help="Define cipher suite to use with XCAP Server") 

    
    (options, args) = parser.parse_args()
    imsi = options.imsi
    imei = options.imei
    msisdn = options.msisdn
    serial_interface = options.serial_interface
    https = options.https 
    check_https = options.check_https
    cipher_suite = options.cipher_suite
    tel = options.tel


    if https == True:
        initialize_tls_cipher_suite()
        
        if check_https == False:
            ctx = ssl._create_unverified_context()
            conn_xcap = http.client.HTTPSConnection(NAF_HOST, context=ctx)
            conn_bsf = http.client.HTTPSConnection(BSF_HOST, context=ctx)
        else:
            ctx = ssl.create_default_context()
            conn_xcap = http.client.HTTPSConnection(NAF_HOST)
            conn_bsf = http.client.HTTPSConnection(BSF_HOST)        
        
        try: #only supported in python 3.8
            ctx.keylog_filename = KEYLOG_PATH       
        except:
            pass
        
        if cipher_suite != "All":
            try:
                open_ssl_cipher_name = get_key(cipher_suite)
                if open_ssl_cipher_name is not None:
                    ctx.set_ciphers(open_ssl_cipher_name)
                else:
                    try:
                        ctx.set_ciphers(cipher_suite)
                    except:
                        print("No cipher suite found! Not setting cipher.")
            except:
                try:
                    ctx.set_ciphers(cipher_suite)
                except:
                    print("No cipher suite found! Not setting cipher.")
    
    else: #http
        protocol_identifier = '0100000002'
        conn_xcap = http.client.HTTPConnection(NAF_HOST)
        conn_bsf = http.client.HTTPConnection(BSF_HOST)
    
    #----------------------------------#          
    #   First GET to NAF/XCAP Server
    #----------------------------------#
    print("\n-> First GET to NAF/XCAP Server:")
    print("   ----------------------------") 
    
    if tel == False:
        headers = {'X-3GPP-Intended-Identity' : 'sip:+' +
                msisdn + '@ims.mnc' + MNC + '.mcc' + MCC +
                '.3gppnetwork.org', 'User-Agent' : '3gpp-gba'
                }
    else:
        headers = {'X-3GPP-Intended-Identity' : 'tel:+' +
                msisdn , 'User-Agent' : '3gpp-gba'
                }    
    
    try:
        conn_xcap.request('GET', '/simservs.ngn.etsi.org/users/sip:+' +
                msisdn + '@ims.mnc' + MNC + '.mcc' + MCC +
                '.3gppnetwork.org/simservs.xml/', headers=headers)    
    except Exception as error:
        print("\tError: ", error)
        print("\nExiting.")
        exit(1)
        
    r = conn_xcap.getresponse()
    data = r.read()
    
    header = r.getheader('WWW-Authenticate')    
    xcap_dict = parse_headers(header)
    
    print("\tNAF/XCAP WWW-Authenticate header received: ", xcap_dict)
    print("\tNAF/XCAP Data received: ", data)
    
    if https == True:
        cipher = conn_xcap.sock.cipher()[0]
        print("\tCipher chosen for XCAP:", cipher)
        
        try:
            protocol_identifier = '010001' + tls_cipher_suite[cipher_openssl_name[cipher]]
        except:
            print("\tUnable to retrieve protocol-identifier for chosen cipher. Exiting.")
            exit(1)
            
    username = imsi + '@ims.mnc' + MNC + '.mcc' + MCC + '.3gppnetwork.org'
    
    #----------------------------#
    #   First GET to BSF Server
    #----------------------------#
    print("\n-> First GET to BSF Server:")
    print("   -----------------------")    
    
    headers = {'Authorization' : 'Digest username="' +
            username + '", realm="' + BSF_HOST +
            '", uri="/", nonce="", response=""',
            'User-Agent' : '3gpp-gba-tmpi', 'X-TMUS-IMEI' : imei
            }        
            
    try:
        conn_bsf.request('GET', '/', headers=headers)
    except Exception as error:
        print("\tError: ", error)
        print("\nExiting.")
        exit(1)
        
    r = conn_bsf.getresponse()
    data = r.read()
    
    header = r.getheader('WWW-Authenticate')
    bsf_dict = parse_headers(header)
    
    print("\tBSF WWW-Authenticate headers received: ", bsf_dict)
    print("\tBSF Data received: ", data)
  
    RAND_AUTN= hexlify(base64.b64decode(bsf_dict['nonce'])).decode('utf-8')
    RAND = RAND_AUTN[0:32]
    AUTN = RAND_AUTN[32:64]
    print("\n\tRAND: ", RAND)
    print("\tAUTN: ", AUTN)
   
    try:
        res, ck, ik = get_res_ck_ik(serial_interface, RAND, AUTN)
    except Exception as error:
        print("\tError: ", error)
        print("\nExiting.")
        exit(1)
    
    if res == None:
        print("\tAuthentication Error. Exiting")
        exit(1)
      
    print("\n\tRES: ", res)
    print("\tCK: ", ck)
    print("\tIK: ", ik)
    
    res = unhexlify(res) 
    
    nc = '00000001' #fixed because is only one iteration
    cnonce = '468f5b9d04a32d38' #fixed because no security concerns...

    #----------------------------#    
    #   Second GET to BSF Server
    #----------------------------#    
    print("\n-> Second GET to BSF Server:")
    print("   ------------------------") 
    
    response = get_response(username, bsf_dict['Digest realm'],
            res, 'GET', '/', bsf_dict['nonce'],
            nc, cnonce, bsf_dict['qop'], b'')   
            
    headers = {'Authorization' : 'Digest username="' +
                imsi + '@ims.mnc' + MNC + '.mcc' + MCC +
                '.3gppnetwork.org",realm="' + bsf_dict['Digest realm'] +
                '",uri="/", nonce="' + bsf_dict['nonce'] + '",response="' +
                response + '",qop=' + bsf_dict['qop'] + ',cnonce="' +
                cnonce + '",opaque="' + bsf_dict['opaque'] + '",algorithm=' +
                bsf_dict['algorithm'] + ',nc=' +
                nc, 'User-Agent' : '3gpp-gba-tmpi', 'X-TMUS-IMEI' : imei
                }

    try:
        conn_bsf.request('GET', '/', headers=headers)
    except Exception as error:
        print("\tError: ", error)
        print("\nExiting.")
        exit(1)
        
    r = conn_bsf.getresponse()
    data = r.read()
    
    header = r.getheader('Authentication-Info')
    bsf_dict = parse_headers(header)
     
    print("\tBSF Authentication-Info header received: ", bsf_dict)
    print("\tBSF Data received: ", data)
    
    btid = data.decode('utf-8').split('<btid>')[1].split('</btid>')[0]

    print("\tBTID: ", btid)


    ks_naf = get_Ks_NAF(ck, ik, RAND, username, NAF_HOST, protocol_identifier)
    tmpi = get_TMPI(ck, ik, RAND, username, btid.split('@')[1])      
    ks_naf = base64.b64encode(ks_naf) #pass in bytes
    
    #----------------------------------#     
    #   Second GET to NAF/XCAP Server
    #----------------------------------#     
    print("\n-> Second GET to NAF/XCAP Server:")
    print("   -----------------------------") 
    
    response = get_response(btid, xcap_dict['Digest realm'],
            ks_naf, 'GET', '/simservs.ngn.etsi.org/users/sip:+' +
            msisdn + '@ims.mnc' + MNC + '.mcc' + MCC +
            '.3gppnetwork.org/simservs.xml/',
            xcap_dict['nonce'], nc, cnonce, xcap_dict['qop'], b'')
            
    if tel == False:
        headers = {'Authorization' : 'Digest username="' + btid +
                '", realm="' + xcap_dict['Digest realm'] +
                '", uri="/simservs.ngn.etsi.org/users/sip:+' +
                msisdn + '@ims.mnc' + MNC + '.mcc' + MCC +
                '.3gppnetwork.org/simservs.xml/", nonce="' +
                xcap_dict['nonce'] + '", response="' + response +
                '", qop=' + xcap_dict['qop'] + ', cnonce="' +
                cnonce + '", opaque="' + xcap_dict['opaque'] +
                '", algorithm=' + xcap_dict['algorithm'] +
                ',nc=' + nc,  'User-Agent' : '3gpp-gba', 'X-TMUS-IMEI' : imei,
                'X-3GPP-Intended-Identity' : 'sip:+' + msisdn +
                '@ims.mnc' + MNC + '.mcc' + MCC + '.3gppnetwork.org'
                }

    else:
        headers = {'Authorization' : 'Digest username="' + btid +
                '", realm="' + xcap_dict['Digest realm'] +
                '", uri="/simservs.ngn.etsi.org/users/sip:+' +
                msisdn + '@ims.mnc' + MNC + '.mcc' + MCC +
                '.3gppnetwork.org/simservs.xml/", nonce="' +
                xcap_dict['nonce'] + '", response="' +
                response + '", qop=' + xcap_dict['qop'] +
                ', cnonce="' + cnonce + '", opaque="' +
                xcap_dict['opaque'] + '", algorithm=' +
                xcap_dict['algorithm'] + ',nc=' + nc,
                'User-Agent' : '3gpp-gba', 'X-TMUS-IMEI' : imei,
                'X-3GPP-Intended-Identity' : 'tel:+' + msisdn
                }

    try:
        conn_xcap.request('GET', '/simservs.ngn.etsi.org/users/sip:+' +
                msisdn + '@ims.mnc' + MNC + '.mcc' + MCC +
                '.3gppnetwork.org/simservs.xml/', headers=headers)
    except Exception as error:
        print("\tError: ", error)
        print("\nExiting.")
        exit(1)
    r = conn_xcap.getresponse()
    data = r.read()    
    
    print("\tNAF/XCAP Response:", data)
    
    

if __name__ == "__main__":
    main()
