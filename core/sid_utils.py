"""
SID Conversion Utilities
Handles conversion between binary and string SID representations.
"""

import struct
import logging
from typing import Optional


class SIDConverter:
    """
    Utility class for converting between binary and string SID formats.
    """

    @staticmethod
    def bytes_to_string(sid_bytes: bytes) -> str:
        """
        Convert binary SID to string representation.

        Args:
            sid_bytes: Binary SID data

        Returns:
            SID as a string (e.g., 'S-1-5-21-...')
        """
        revision = sid_bytes[0]
        sub_authority_count = sid_bytes[1]
        identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')

        sid = f"S-{revision}-{identifier_authority}"

        for i in range(sub_authority_count):
            offset = 8 + (i * 4)
            sub_authority = struct.unpack('<I', sid_bytes[offset:offset + 4])[0]
            sid += f"-{sub_authority}"

        return sid

    @staticmethod
    def string_to_bytes(sid_string: str) -> Optional[bytes]:
        """
        Convert string SID to binary representation.

        Args:
            sid_string: SID as a string (e.g., 'S-1-5-21-...')

        Returns:
            Binary SID data, or None if conversion fails
        """
        try:
            parts = sid_string.split('-')
            if parts[0] != 'S':
                logging.error("Invalid SID format: must start with 'S'")
                return None

            revision = int(parts[1])
            identifier_authority = int(parts[2])
            sub_authorities = [int(x) for x in parts[3:]]

            sid_bytes = struct.pack('B', revision)
            sid_bytes += struct.pack('B', len(sub_authorities))
            sid_bytes += identifier_authority.to_bytes(6, byteorder='big')

            for sub_authority in sub_authorities:
                sid_bytes += struct.pack('<I', sub_authority)

            return sid_bytes

        except (ValueError, IndexError) as e:
            logging.error(f"Error converting SID string to bytes: {e}")
            return None

    @staticmethod
    def domain_to_dn(domain: str) -> str:
        """
        Convert domain name to distinguished name.

        Args:
            domain: Domain name (e.g., 'example.com')

        Returns:
            Distinguished name (e.g., 'DC=example,DC=com')
        """
        return ','.join([f'DC={part}' for part in domain.split('.')])

