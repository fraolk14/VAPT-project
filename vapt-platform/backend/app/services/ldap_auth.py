from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPException

from app.config.ldap import (
    LDAP_SERVER,
    LDAP_BASE_DN,
    LDAP_ADMIN_GROUP,
    LDAP_ANALYST_GROUP
)


def authenticate_ldap(username: str, password: str):
    """
    Authenticate a user against Active Directory (LDAP).

    Returns:
        dict: { "username": str, "role": str } on success
        None: on authentication failure or LDAP error
    """

    try:
        # Construct user principal name (UPN)
        user_dn = f"{username}@company.local"

        # Connect to LDAP server
        server = Server(LDAP_SERVER, get_info=ALL)

        conn = Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=True
        )

        # Search user to get group membership
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=f"(sAMAccountName={username})",
            attributes=["memberOf"]
        )

        if not conn.entries:
            return None

        groups = conn.entries[0].memberOf.values

        # Map AD groups to application roles
        if LDAP_ADMIN_GROUP in groups:
            role = "admin"
        elif LDAP_ANALYST_GROUP in groups:
            role = "analyst"
        else:
            role = "viewer"

        return {
            "username": username,
            "role": role
        }

    except LDAPException:
        # Covers invalid credentials, unreachable server, bind failures, etc.
        return None

    except Exception:
        # Catch-all safety net — never let LDAP crash auth
        return None
