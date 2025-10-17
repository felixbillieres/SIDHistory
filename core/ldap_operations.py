"""
LDAP Operations
Handles LDAP queries and modifications for Active Directory.
"""

import logging
from typing import Optional, List
from ldap3 import Connection, MODIFY_REPLACE, SUBTREE
from ldap3.core.exceptions import LDAPException

from .sid_utils import SIDConverter


class LDAPOperations:
    """
    Performs LDAP operations on Active Directory.
    """

    def __init__(self, connection: Connection, base_dn: str):
        """
        Initialize LDAP operations handler.

        Args:
            connection: Active LDAP connection
            base_dn: Base distinguished name for searches
        """
        self.connection = connection
        self.base_dn = base_dn
        self.sid_converter = SIDConverter()

    def get_user_sid(self, sam_account_name: str) -> Optional[str]:
        """
        Retrieve the SID of a user by sAMAccountName.

        Args:
            sam_account_name: The sAMAccountName of the user

        Returns:
            SID as a string, or None if not found
        """
        try:
            search_filter = f"(sAMAccountName={sam_account_name})"
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['objectSid']
            )

            if not self.connection.entries:
                logging.error(f"User {sam_account_name} not found")
                return None

            sid_bytes = self.connection.entries[0].objectSid.raw_values[0]
            sid = self.sid_converter.bytes_to_string(sid_bytes)
            logging.info(f"Found SID for {sam_account_name}: {sid}")
            return sid

        except LDAPException as e:
            logging.error(f"Error retrieving SID for {sam_account_name}: {e}")
            return None

    def get_user_dn(self, sam_account_name: str) -> Optional[str]:
        """
        Retrieve the distinguished name of a user by sAMAccountName.

        Args:
            sam_account_name: The sAMAccountName of the user

        Returns:
            Distinguished name as a string, or None if not found
        """
        try:
            search_filter = f"(sAMAccountName={sam_account_name})"
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )

            if not self.connection.entries:
                logging.error(f"User {sam_account_name} not found")
                return None

            dn = str(self.connection.entries[0].distinguishedName)
            logging.info(f"Found DN for {sam_account_name}: {dn}")
            return dn

        except LDAPException as e:
            logging.error(f"Error retrieving DN for {sam_account_name}: {e}")
            return None

    def get_sid_history(self, sam_account_name: str) -> List[str]:
        """
        Retrieve the current SID History of a user.

        Args:
            sam_account_name: The sAMAccountName of the user

        Returns:
            List of SIDs in the user's SID History
        """
        try:
            search_filter = f"(sAMAccountName={sam_account_name})"
            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['sIDHistory']
            )

            if not self.connection.entries:
                logging.error(f"User {sam_account_name} not found")
                return []

            entry = self.connection.entries[0]
            if not hasattr(entry, 'sIDHistory'):
                logging.info(f"No SID History found for {sam_account_name}")
                return []

            sid_history = []
            for sid_bytes in entry.sIDHistory.raw_values:
                sid = self.sid_converter.bytes_to_string(sid_bytes)
                sid_history.append(sid)

            logging.info(f"Current SID History for {sam_account_name}: {sid_history}")
            return sid_history

        except LDAPException as e:
            logging.error(f"Error retrieving SID History for {sam_account_name}: {e}")
            return []

    def modify_sid_history(self, user_dn: str, sid_list: List[str]) -> bool:
        """
        Modify the SID History attribute of a user.

        Args:
            user_dn: Distinguished name of the user
            sid_list: List of SIDs to set as SID History

        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert all SIDs to bytes
            sid_bytes_list = []
            for sid in sid_list:
                sid_bytes = self.sid_converter.string_to_bytes(sid)
                if not sid_bytes:
                    logging.error(f"Failed to convert SID {sid} to bytes")
                    return False
                sid_bytes_list.append(sid_bytes)

            changes = {
                'sIDHistory': [(MODIFY_REPLACE, sid_bytes_list)]
            }

            success = self.connection.modify(user_dn, changes)

            if success:
                logging.info(f"Successfully modified SID History for {user_dn}")
                return True
            else:
                logging.error(f"Failed to modify SID History: {self.connection.result}")
                return False

        except LDAPException as e:
            logging.error(f"Error modifying SID History: {e}")
            return False

    def search_by_sid(self, sid: str) -> Optional[str]:
        """
        Search for a user or group by SID.

        Args:
            sid: SID to search for

        Returns:
            sAMAccountName of the object, or None if not found
        """
        try:
            sid_bytes = self.sid_converter.string_to_bytes(sid)
            if not sid_bytes:
                return None

            # LDAP search filter for objectSid requires hex representation
            sid_hex = ''.join([f'\\{b:02x}' for b in sid_bytes])
            search_filter = f"(objectSid={sid_hex})"

            self.connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName', 'objectClass']
            )

            if not self.connection.entries:
                logging.warning(f"No object found with SID {sid}")
                return None

            entry = self.connection.entries[0]
            sam_account = str(entry.sAMAccountName)
            obj_class = str(entry.objectClass)
            
            logging.info(f"Found object {sam_account} ({obj_class}) with SID {sid}")
            return sam_account

        except LDAPException as e:
            logging.error(f"Error searching by SID: {e}")
            return None

