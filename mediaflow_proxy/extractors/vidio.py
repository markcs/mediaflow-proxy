import time
import hmac
import hashlib
from typing import Dict, Any
from urllib.parse import urlparse
import json
import re
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

class VidioExtractor(BaseExtractor):
    """Vidio HLS URL extractor."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "hls_manifest_proxy"
        self._api_key = None
        self._api_key_expiry = None
        # TODO: Add storage for access/refresh if supporting signed-in mode

    def _parse_livestream_id(self, url: str) -> str:
        path = urlparse(url).path
        match = re.search(r'/live/(\d+)-', path)
        if not match:
            raise ExtractorError(f"Failed to parse livestream ID from URL: {url}")
        return match.group(1)

    def _generate_signature(self, client_id: str) -> str:
        key = f"V1d10D3v:{client_id}"
        message = client_id
        hash_obj = hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256)
        return hash_obj.hexdigest()

    async def _fetch_token(self) -> Dict[str, Any]:
        """Replicate t.fetchToken() - exact match to your curl."""
        token_url = "https://api.vidio.com/auth"
        token_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            # TODO: If v_ adds more defaults (e.g., Accept, credentials), include them here
        }
        response = await self._make_request(token_url, method="POST", headers=token_headers)  # No body, as in curl
        try:
            data = json.loads(response.text)
            # Handle like JS: Check for 'error' (though your example has none)
            if "error" in data:
                raise ExtractorError(f"Token fetch error: {data['error'].get('message', 'Unknown')}")
            return data  # Returns {"api_key": "...", "api_key_expires_at": "..."}
        except json.JSONDecodeError:
            raise ExtractorError("Invalid token response from Vidio API")

    def _is_expired(self) -> bool:
        """Replicate t.isExpired() - simplified for guest mode (assume not signed in)."""
        if not self._api_key_expiry:
            return True
        # Add 1-hour buffer as in durationSinceExpired
        buffered_time = datetime.now(self._api_key_expiry.tzinfo) + timedelta(hours=1)  # Respect timezone
        return buffered_time >= self._api_key_expiry
        # TODO: If signed-in, add checks for access/refresh (use r.dr.isUserSignedIn equivalent)

    async def _get_api_key(self, force: bool = False) -> str:
        """Replicate t.getApiKey()."""
        if self._api_key and not self._is_expired() and not force:
            return self._api_key
        
        token_data = await self._fetch_token()
        self._api_key = token_data.get("api_key")
        expiry_str = token_data.get("api_key_expires_at")
        if expiry_str:
            # Parse ISO with timezone (e.g., "2025-08-08T08:20:07+07:00")
            self._api_key_expiry = datetime.fromisoformat(expiry_str)
        else:
            self._api_key_expiry = datetime.now() + timedelta(days=1)  # Fallback
        
        if not self._api_key:
            raise ExtractorError("Failed to fetch API key")
        return self._api_key

    def _encrypt(self, value: str) -> str:
        """Replicate a.C.encrypt() - AES-256-CBC with fixed key/IV, PKCS7 padding, and base64 encoding."""
        key = "dPr0QImQ7bc5o9LMntNba2DOsSbZcjUh".encode('utf-8')  # 32 bytes for AES-256
        iv = "C8RWsrtFsoeyCyPt".encode('utf-8')  # 16 bytes
        
        # Pad the input value
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(value.encode('utf-8')) + padder.finalize()
        
        # Encrypt with AES-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Base64-encode the ciphertext (matches JS toString())
        return base64.b64encode(ciphertext).decode('utf-8')

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        livestream_id = self._parse_livestream_id(url)
        api_url = f"https://api.vidio.com/livestreamings/{livestream_id}/stream?initialize=true"

        x_client = f"{time.time():.3f}"
        x_signature = self._generate_signature(x_client)
        base_api_key = await self._get_api_key()
        x_api_key = self._encrypt(base_api_key)  # No client_id dependency

        headers = {
            "accept": "*/*",
            "content-type": "application/vnd.api+json",
            "origin": "https://www.vidio.com",
            "referer": "https://www.vidio.com/",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
            "x-api-key": x_api_key,
            "x-api-platform": "web-desktop",
            "x-client": x_client,
            "x-request-from": url,
            "x-secure-level": "2",
            "x-signature": x_signature,
            **kwargs.get("headers", {})
        }

        response = await self._make_request(api_url, headers=headers)
        
        try:
            data = json.loads(response.text)
            hls_url = data.get("data", {}).get("attributes", {}).get("hls")
            if not hls_url:
                raise ExtractorError("Failed to extract HLS URL from API response")
        except json.JSONDecodeError:
            raise ExtractorError("Invalid JSON response from Vidio API")

        self.base_headers["referer"] = url
        return {
            "destination_url": hls_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }