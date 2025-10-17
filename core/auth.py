"""
Authentication Manager
Handles various authentication methods for Active Directory:
- NTLM with password
- NTLM with hash (Pass-the-Hash)
- Kerberos
- Pass-the-Certificate (via LDAPS with client cert)
"""

import logging
import os
from typing import Optional, Tuple
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SASL, KERBEROS, Tls
import ssl


class AuthenticationManager:
    """
    Manages different authentication methods for LDAP connections.
    """

    AUTH_NTLM = 'ntlm'
    AUTH_NTLM_HASH = 'ntlm-hash'
    AUTH_KERBEROS = 'kerberos'
    AUTH_SIMPLE = 'simple'
    AUTH_CERTIFICATE = 'certificate'

    def __init__(self, dc_ip: str, domain: str, dc_hostname: Optional[str] = None):
        """
        Initialize authentication manager.

        Args:
            dc_ip: Domain controller IP address
            domain: Domain name
            dc_hostname: Domain controller hostname (for Kerberos and SSL)
        """
        self.dc_ip = dc_ip
        self.domain = domain
        self.dc_hostname = dc_hostname or dc_ip

    def create_server(self, use_ssl: bool = False, port: Optional[int] = None,
                     cert_file: Optional[str] = None, key_file: Optional[str] = None) -> Server:
        """
        Create LDAP server object.

        Args:
            use_ssl: Use LDAPS
            port: Custom port (default: 389 for LDAP, 636 for LDAPS)
            cert_file: Client certificate file for mTLS
            key_file: Client key file for mTLS

        Returns:
            Server object
        """
        protocol = 'ldaps' if use_ssl else 'ldap'
        
        if port is None:
            port = 636 if use_ssl else 389

        tls_config = None
        if use_ssl:
            tls_config = Tls(
                validate=ssl.CERT_NONE,
                version=ssl.PROTOCOL_TLSv1_2,
                local_certificate_file=cert_file,
                local_private_key_file=key_file
            )

        server = Server(
            f'{protocol}://{self.dc_hostname}:{port}',
            get_info=ALL,
            use_ssl=use_ssl,
            tls=tls_config
        )

        return server

    def connect_ntlm(self, username: str, password: str, 
                    use_ssl: bool = False) -> Optional[Connection]:
        """
        Connect using NTLM authentication with password.

        Args:
            username: Username
            password: Password
            use_ssl: Use LDAPS

        Returns:
            Connection object or None if failed
        """
        try:
            server = self.create_server(use_ssl=use_ssl)
            user_dn = f"{self.domain}\\{username}"

            connection = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=NTLM,
                auto_bind=True
            )

            logging.info(f"Successfully authenticated via NTLM as {username}")
            return connection

        except Exception as e:
            logging.error(f"NTLM authentication failed: {e}")
            return None

    def connect_ntlm_hash(self, username: str, nt_hash: str, 
                         use_ssl: bool = False) -> Optional[Connection]:
        """
        Connect using Pass-the-Hash (NTLM with hash).

        Args:
            username: Username
            nt_hash: NT hash (LM:NT or just NT)
            use_ssl: Use LDAPS

        Returns:
            Connection object or None if failed
        """
        try:
            server = self.create_server(use_ssl=use_ssl)
            user_dn = f"{self.domain}\\{username}"

            # Format: LM:NT or just NT
            if ':' in nt_hash:
                lm_hash, nt_hash = nt_hash.split(':', 1)
            else:
                lm_hash = 'aad3b435b51404eeaad3b435b51404ee'  # Empty LM hash

            # ldap3 expects password in format LM:NT for PTH
            password = f"{lm_hash}:{nt_hash}"

            connection = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=NTLM,
                auto_bind=True
            )

            logging.info(f"Successfully authenticated via Pass-the-Hash as {username}")
            return connection

        except Exception as e:
            logging.error(f"Pass-the-Hash authentication failed: {e}")
            logging.debug(f"Details: {str(e)}")
            return None

    def connect_kerberos(self, use_ssl: bool = False, 
                        ccache_path: Optional[str] = None) -> Optional[Connection]:
        """
        Connect using Kerberos authentication.

        Args:
            use_ssl: Use LDAPS
            ccache_path: Path to Kerberos credential cache (optional)

        Returns:
            Connection object or None if failed

        Note:
            Requires valid Kerberos ticket (kinit or ccache file).
            Set KRB5CCNAME environment variable for custom ccache location.
        """
        try:
            # Set ccache path if provided
            if ccache_path:
                os.environ['KRB5CCNAME'] = ccache_path
                logging.debug(f"Using Kerberos ccache: {ccache_path}")

            server = self.create_server(use_ssl=use_ssl)

            connection = Connection(
                server,
                authentication=SASL,
                sasl_mechanism=KERBEROS,
                auto_bind=True
            )

            logging.info("Successfully authenticated via Kerberos")
            return connection

        except Exception as e:
            logging.error(f"Kerberos authentication failed: {e}")
            logging.debug("Ensure you have a valid Kerberos ticket (kinit)")
            return None

    def connect_certificate(self, cert_file: str, key_file: str,
                           username: Optional[str] = None) -> Optional[Connection]:
        """
        Connect using client certificate (Pass-the-Certificate).

        Args:
            cert_file: Path to client certificate file (.pem)
            key_file: Path to client private key file (.pem)
            username: Username (optional, for SIMPLE bind with cert)

        Returns:
            Connection object or None if failed

        Note:
            Requires LDAPS. Certificate must be trusted by the DC.
        """
        try:
            server = self.create_server(
                use_ssl=True,
                cert_file=cert_file,
                key_file=key_file
            )

            if username:
                user_dn = f"{username}@{self.domain}"
                connection = Connection(
                    server,
                    user=user_dn,
                    authentication=SIMPLE,
                    auto_bind=True
                )
            else:
                # Anonymous bind with client cert
                connection = Connection(
                    server,
                    authentication=SASL,
                    auto_bind=True
                )

            logging.info("Successfully authenticated via client certificate")
            return connection

        except Exception as e:
            logging.error(f"Certificate authentication failed: {e}")
            return None

    def connect_simple(self, username: str, password: str,
                      use_ssl: bool = True) -> Optional[Connection]:
        """
        Connect using SIMPLE authentication (bind with DN and password).

        Args:
            username: Username or full DN
            password: Password
            use_ssl: Use LDAPS (recommended for SIMPLE auth)

        Returns:
            Connection object or None if failed

        Note:
            SIMPLE auth sends password in clear text without SSL.
            Use LDAPS (use_ssl=True) for security.
        """
        try:
            server = self.create_server(use_ssl=use_ssl)
            
            # Check if username is already a DN
            if username.lower().startswith('cn=') or username.lower().startswith('uid='):
                user_dn = username
            else:
                user_dn = f"{username}@{self.domain}"

            connection = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=SIMPLE,
                auto_bind=True
            )

            logging.info(f"Successfully authenticated via SIMPLE as {username}")
            return connection

        except Exception as e:
            logging.error(f"SIMPLE authentication failed: {e}")
            return None

    def get_connection(self, auth_method: str, username: Optional[str] = None,
                      password: Optional[str] = None, nt_hash: Optional[str] = None,
                      use_ssl: bool = False, ccache_path: Optional[str] = None,
                      cert_file: Optional[str] = None, key_file: Optional[str] = None) -> Optional[Connection]:
        """
        Get connection using specified authentication method.

        Args:
            auth_method: Authentication method (ntlm, ntlm-hash, kerberos, certificate, simple)
            username: Username (required for most methods)
            password: Password (for ntlm, simple)
            nt_hash: NT hash (for ntlm-hash)
            use_ssl: Use LDAPS
            ccache_path: Kerberos ccache path
            cert_file: Certificate file path
            key_file: Key file path

        Returns:
            Connection object or None if failed
        """
        if auth_method == self.AUTH_NTLM:
            return self.connect_ntlm(username, password, use_ssl)

        elif auth_method == self.AUTH_NTLM_HASH:
            return self.connect_ntlm_hash(username, nt_hash, use_ssl)

        elif auth_method == self.AUTH_KERBEROS:
            return self.connect_kerberos(use_ssl, ccache_path)

        elif auth_method == self.AUTH_CERTIFICATE:
            return self.connect_certificate(cert_file, key_file, username)

        elif auth_method == self.AUTH_SIMPLE:
            return self.connect_simple(username, password, use_ssl)

        else:
            logging.error(f"Unknown authentication method: {auth_method}")
            return None

