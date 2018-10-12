#!/usr/bin/env python2

from hashlib import md5
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import URLSafeTimedSerializer

class SimpleSecureCookieSessionInterface(SecureCookieSessionInterface):
	# Override method
	# Take secret_key instead of an instance of a Flask app
	def get_signing_serializer(self, secret_key):
		if not secret_key:
			return None
		signer_kwargs = dict(
			key_derivation=self.key_derivation,
			digest_method=self.digest_method
		)
		return URLSafeTimedSerializer(secret_key, salt=self.salt,
		                              serializer=self.serializer,
		                              signer_kwargs=signer_kwargs)

def decodeFlaskCookie(secret_key, cookieValue):
	sscsi = SimpleSecureCookieSessionInterface()
	signingSerializer = sscsi.get_signing_serializer(secret_key)
	return signingSerializer.loads(cookieValue)

# Keep in mind that flask uses unicode strings for the
# dictionary keys
def encodeFlaskCookie(secret_key, cookieDict):
	sscsi = SimpleSecureCookieSessionInterface()
	signingSerializer = sscsi.get_signing_serializer(secret_key)
	return signingSerializer.dumps(cookieDict)

# Real
cookie = 'UeVf0Wm/zvk2NSWoSiEO22g+HO3OgzXSDPuKDuBcmI79RQB4VG+yZRO5UuOELshPCcmJBLaiswpmP183uE44qQ=='
session = '.eJwlj8uqAjEQBf8laxdJJ_3yZ4akHyiCwoyuLvffHXB_iqrzV7bc47iV63v_xKVsdy_XwsHRaRm3lSLUois0U-TB2BzCJcmSYCXNQACDiEpOQaqgXSh92cCc0s_RxDpTZwDhsC7RKw6WnB3BktE6mzKBhjp3XRVauRQ79tzer0c8z546fNIp4xC2QK4abQiuirAGwwKvjgx5cp8j9t-J1sr_F-VfPsY.Dpf9WQ.3C2_z3QsY0_xfmzu0_UkXdwijwo'
secret_key = 'a7a8342f9b41fcb062b13dd1167785f8'

d = decodeFlaskCookie(secret_key, session)
print d
d['user_id'] = u'1'
print d
e = encodeFlaskCookie(secret_key, d)
print e
