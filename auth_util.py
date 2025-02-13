import os
import re
import time
import base64
from typing import MutableMapping

import jwt
from cryptography.hazmat.primitives import serialization, hashes
from abc import ABC, abstractmethod

import secrets
import base64


def generate_secure_token(length: int) -> str:
	"""Generate a URL-safe base64-encoded random token of the specified length."""
	# Calculate the number of random bytes needed
	num_bytes = (length * 3) // 4 + 1  # Ensure sufficient bytes for base64 encoding
	random_bytes = secrets.token_bytes(num_bytes)

	# Encode to URL-safe base64 and strip padding
	token = base64.urlsafe_b64encode(random_bytes).decode('utf-8')

	return token[:length]  # Trim to the exact length

import time
import heapq
import threading


class TimeoutRegistry:
	def __init__(self, check_interval=1.0):
		"""
		Initialize the registry.

		Args:
			check_interval (float): How often (in seconds) the background thread
									should check for expired entries.
		"""
		self._entries = {}  # Maps key -> (entry, expiration_time)
		self._heap = []  # A heap of (expiration_time, key)
		self._lock = threading.Lock()
		self._stop_event = threading.Event()
		self._check_interval = check_interval

		# Start the background thread to monitor expirations.
		self._thread = threading.Thread(target=self._timeout_watcher, daemon=True)
		self._thread.start()

	def add(self, key: str, entry, timeout: float):
		"""
		Add an entry to the registry with a given timeout.

		Args:
			key (str): The unique identifier for the entry.
			entry: The data to store.
			timeout (float): The time in seconds until the entry should timeout.
		"""
		expiration = time.time() + timeout
		with self._lock:
			self._entries[key] = (entry, expiration)
			heapq.heappush(self._heap, (expiration, key))

	def remove(self, key: str):
		"""
		Remove an entry from the registry immediately.

		Args:
			key (str): The identifier of the entry to remove.
		"""
		with self._lock:
			if key in self._entries:
				del self._entries[key]

	def refresh(self, key: str, timeout: float):
		"""
		Refresh the timeout for an existing entry.

		Args:
			key (str): The identifier of the entry to refresh.
			timeout (float): The new timeout (in seconds) from now.

		Raises:
			KeyError: If the key is not found in the registry.
		"""
		with self._lock:
			if key in self._entries:
				entry, _ = self._entries[key]
				new_expiration = time.time() + timeout
				self._entries[key] = (entry, new_expiration)
				heapq.heappush(self._heap, (new_expiration, key))
			else:
				raise KeyError(f"Key '{key}' not found in registry.")

	def get(self, key: str, default=None):
		"""
		Retrieve the latest entry for the given key.

		Args:
			key (str): The key to search for.
			default (object): The value returned if the key is not found.

		Returns:
			The most recent entry matching the key, or None if not found.
		"""
		return self._entries.get(key, [default])[0]

	def entry_timed_out(self, key: str, entry):
		"""
		Strategy called when an entry times out.

		Override this method if you want custom behavior on timeout.
		The default implementation returns True, meaning the entry will be removed.

		Args:
			key (str): The identifier of the entry that timed out.
			entry: The entry data.

		Returns:
			If False is returned, the entry is kept; any other value causes removal.
		"""
		return True

	def _timeout_watcher(self):
		"""
		Background thread method that checks the heap for expired entries.
		"""
		while not self._stop_event.is_set():
			self._process_expired_entries()
			self._wait_for_next_check()

	def _process_expired_entries(self):
		"""
		Process all expired entries and remove them if necessary.
		"""
		now = time.time()
		with self._lock:
			while self._heap and self._heap[0][0] <= now:
				self._process_expired_entry()

	def _process_expired_entry(self):
		"""
		Processes a single expired entry.
		"""
		expiration, key = heapq.heappop(self._heap)
		if key in self._entries and self._entries[key][1] == expiration:
			entry = self._entries[key][0]
			if self.entry_timed_out(key, entry) is not False:
				del self._entries[key]

	def _wait_for_next_check(self):
		"""
		Determines the sleep duration before the next expiration check.
		"""
		with self._lock:
			if self._heap:
				next_expiration = self._heap[0][0]
				delay = max(0, next_expiration - time.time())
				sleep_time = min(self._check_interval, delay)
			else:
				sleep_time = self._check_interval
		self._stop_event.wait(timeout=sleep_time)

	def stop(self):
		"""
		Stop the background watcher thread.
		"""
		self._stop_event.set()
		self._thread.join()

	def __del__(self):
		"""
		Ensure the background thread is stopped when the object is deleted.
		"""
		self.stop()
		

class SingletonMeta(type):
	_instances = {}

	def __call__(cls, *args, **kwargs):
		# If an instance of this class already exists, return it
		if cls not in cls._instances:
			instance = super().__call__(*args, **kwargs)
			cls._instances[cls] = instance
		return cls._instances[cls]




# Configuration
CREDENTIALS_DIR = "credentials"
timeout_jwt = 3*60
timeout_store_token = 3*60*60
# Save users public key as f'{CREDENTIALS_DIR}/{username}.pub'


# Key creation:
# ssh-keygen -t ed25519 -f path/to/user_private_key -N ""

# Simple test:
# ssh-keygen -t ed25519 -f credentials/alice -N ""
# > python pk_sign_in_client_side.py alice ./credentials/alice | python pk_sign_in_server_side.py


# Load private key
def load_private_key(private_key_path: str, password: str = None):
	with open(private_key_path, "rb") as f:
		key_data = f.read()

	private_key = serialization.load_ssh_private_key(key_data, password=password)
	return private_key


def create_signature(username, private_key_path):
	private_key = load_private_key(private_key_path)
	timestamp = time.time()
	message = f"{username}:{timestamp}".encode("utf-8")

	# Sign the message with the user's private key
	signature = private_key.sign(message)
	signature_b64 = base64.b64encode(signature).decode('utf-8')

	request = {
		"username": username,
		"timestamp": str(timestamp),
		"signature": signature_b64
	}

	return request


def generate_jwt(username, private_key):
	timestamp = time.time()
	payload = {"username": username, "timestamp": str(timestamp)}

	# Convert private key to PEM format
	pem_private_key = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	).decode("utf-8")

	# Sign JWT using the PEM-formatted private key
	token = jwt.encode(payload, pem_private_key, algorithm="EdDSA")
	return token


def verify_jwt(token, public_key):
	try:
		# Convert public key to PEM format
		pem_public_key = public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		).decode("utf-8")

		decoded_data = jwt.decode(token, pem_public_key, algorithms=["EdDSA"])
		return decoded_data
	except jwt.ExpiredSignatureError:
		return {"error": "Token expired"}
	except jwt.InvalidTokenError:
		return {"error": "Invalid token"}


def load_public_key(username):
	pub_path = os.path.join(CREDENTIALS_DIR, f"{username}.pub")
	if not os.path.exists(pub_path):
		return None
	with open(pub_path, "rb") as f:
		key_data = f.read()
	# Assuming SSH public key format, we need to convert it to an Ed25519 key
	# SSH Ed25519 public keys typically start with "ssh-ed25519"
	key_line = key_data.decode().strip()
	parts = key_line.split()
	if len(parts) < 2 or parts[0] != "ssh-ed25519":
		return None
	pub_bytes = serialization.load_ssh_public_key(key_line.encode())
	return pub_bytes


def verify_signature(public_key, message, signature):
	try:
		public_key.verify(signature, message, hashes.Hash(hashes.SHA256()))
		return True
	except Exception:
		return False


def get_jwt_from_request(request, public_key) -> object:
	"""
	Validates a requests auth token
	:param request: the request instance
	:param public_key: the hazmat public key
	:return: json data of decrypted token / raises ValueError on fault
	"""
	token = request.headers.get("Authorization")

	if not token:
		raise PermissionError("request header has no Bearer token")

	token = token.replace("Bearer ", "")
	user_data = verify_jwt(token, public_key)

	if "error" in user_data:
		raise ValueError(user_data['error'])

	return user_data


class Authorization(ABC):
	@abstractmethod
	def get_user(self):
		pass

	@abstractmethod
	def get_token(self):
		pass

	@staticmethod
	def from_request(request):
		token = request.headers.get("Authorization")

		if not token:
			return AuthGuest()

		if 'Bearer' in token:
			return AuthByJwt.from_request(request)
		elif 'Lease' in token:
			return AuthByStore.from_request(request)
		elif 'guest' in token:
			return AuthGuest()

		raise PermissionError('no authentication method found')

	@staticmethod
	def from_token(token, user_public_key):
		return AuthByJwt.from_token(token, user_public_key)


class AuthorizationMethod(Authorization, ABC):
	"""
	A tagging interface for authorization performed by some sign-in method, that is not store-intern
	like AuthGuest or AuthByStore.
	"""
	pass


class AuthGuest(Authorization):
	"""
	Fallback auth.
	"""
	def get_user(self):
		return 'guest'

	def get_token(self):
		return 'guest'


class AuthByJwt(AuthorizationMethod):
	def __init__(self, token:str, user_data:MutableMapping):
		self.token = token
		self.user_data = user_data
		pass

	@staticmethod
	def from_token(token, user_public_key):
		print(token)
		user_data = verify_jwt(token, user_public_key)  # using unencrypted public keys for now

		if "error" in user_data:
			raise PermissionError(str(user_data))

		auth = AuthByJwt(token, user_data)
		return auth

	@staticmethod
	def from_request(request):
		try:
			token = request.headers.get("Authorization")

			if not token:
				raise ValueError()

			auth = AuthByJwt.from_token(token)
			return auth

		except ValueError:
			return AuthGuest()

	def get_user(self):
		return self.user_data.get('username')

	def get_token(self):
		return self.token


class AuthByStore(Authorization):
	def __init__(self, user:str, token:str = None):
		if user is None:
			raise ValueError('no user provided')

		self.user = user
		self.token = token if token else generate_secure_token(32)

	def get_user(self):
		return self.user

	def get_token(self):
		return f"Lease {self.token}"

	@staticmethod
	def _extract_store_token(auth_header: str):
		"""
		Extracts and validates the JWT token from the Authorization header.

		Returns:
			str: The extracted JWT token if valid.
			None: If the header is missing or invalid.
		"""
		if not auth_header:
			return None  # No Authorization header present

		# Regular expression to match 'Bearer <token>'
		lease_pattern = r"^Lease\s+(.*)$"
		match = re.match(lease_pattern, auth_header)

		if match:
			return match.group(1)  # Extracted JWT token
		return None  # Invalid format

	@staticmethod
	def from_token(header_entry: str, auth_registry: "AuthRegistry"):
		# token = AuthByStore._extract_store_token(header_entry)
		auth = auth_registry.get(header_entry)
		if auth is None:
			return AuthGuest()

		return auth

	@staticmethod
	def from_request(request):
		try:
			token = request.headers.get("Authorization")

			if not token:
				raise ValueError()

			auth = AuthByStore.from_token(token, AuthRegistry())
			return auth

		except ValueError:
			return AuthGuest()

	@staticmethod
	def for_user(user_name: str):
		result = AuthByStore(user_name)
		AuthRegistry().add(result.get_token(), result, timeout=1800)
		return result


class AuthRegistry(TimeoutRegistry, metaclass=SingletonMeta):
	@staticmethod
	def key_for_auth_asset(token, asset_path):
		return f'{token}/{asset_path}'

	def add_paths_for_auth(self, auth: Authorization, paths: [str], timeout: int):
		token = auth.get_token()
		for p in paths:
			key = AuthRegistry.key_for_auth_asset(token, p)
			self.add(key, auth, timeout)
