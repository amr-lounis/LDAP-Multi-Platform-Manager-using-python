# LDAP Multi-Platform Manager

A flexible Python wrapper for the `ldap3` library designed to simplify user management across different LDAP implementations, including **Active Directory**, **OpenLDAP**, and **FreeIPA**.

## 🚀 Features

* **Multi-Server Support**: Built-in configurations for AD, OpenLDAP, and FreeIPA.
* **Secure Connectivity**: Supports Plain, SSL, and TLS connections.
* **CRUD Operations**: Easily create, delete, and list users.
* **Active Directory Integration**: Specialized methods for enabling/disabling accounts and modifying passwords via Microsoft extensions.
* **Context Manager Support**: Uses Python's `with` statement for safe connection handling (auto-bind/unbind).
* **Utility Tools**: Includes a robust random password generator.

## 🛠 Installation

Ensure you have the `ldap3` library installed:

```bash
pip install ldap3
```

## 💻 Usage

### Basic Initialization
```python
from ldap_manager import LDAPManager

# Example for Active Directory
ldap_params = {
    'ldap_address': '192.168.1.100',
    'ldap_user': 'admin@domain.com',
    'ldap_password': 'securepassword',
    'connection_type': 'ssl',
    'domain': 'domain.com',
    'server_type': 'ad'
}


_user='user1'

with LDAPManager(**ldap_params) as ldap:
    # Get all users
    users = ldap.users_get(base_dn='CN=Users,DC=ad,DC=local')
    print('users: ',users)
    # Create a new user
    ldap.user_create(username=_user,first_name=_user,last_name=_user, base_dn='CN=Users,DC=ad,DC=local')
    
    ldap.user_disable(_user, base_dn='CN=Users,DC=ad,DC=local')
    ldap.user_enable(_user, base_dn='CN=Users,DC=ad,DC=local')

    newPass = ldap.password_generate()
    b = ldap.user_password(username=_user,new_password=newPass, base_dn='CN=Users,DC=ad,DC=local')
    if b == True:
        print('ok new password is ',newPass)
    
    ldap.user_delete(_user, base_dn='CN=Users,DC=ad,DC=local')

    # ldap.delete_by_dn(dn=f"CN={_user} {_user},CN=Users,DC=ad,DC=local")
    # r= ldap._get_dn(base='CN=Users,DC=ad,DC=local', filter_=f"(&(objectClass=user)(sAMAccountName={_user}))")
    # r= ldap._search(base='CN=Users,DC=ad,DC=local', filter_=f"(&(objectClass=user)(sAMAccountName={_user}))", attrs=['distinguishedName'])
    # print('---------------------',r)

```

### Account Management
```python
# Disable an account (AD only)
ldap.user_disable("jdoe", "OU=Users,DC=domain,DC=com")

# Update password
new_pwd = ldap.password_generate()
ldap.user_password("jdoe", new_pwd, "OU=Users,DC=domain,DC=com")
```

## 📋 Class Methods Reference

| Method | Description |
| :--- | :--- |
| `users_get(base_dn)` | Returns a list of usernames from the specified Base DN. |
| `user_create(...)` | Creates a user with appropriate ObjectClasses based on server type. |
| `user_delete(username, base_dn)` | Removes a user from the directory. |
| `user_state(username, state, ...)` | Enables/Disables AD accounts using `userAccountControl`. |
| `user_password(username, pwd, ...)` | Updates user password (supports AD-specific extensions). |
| `password_generate()` | Generates a complex, random password with symbols. |

## 🛡 Security Note
This implementation uses `ssl.CERT_NONE` by default for TLS/SSL connections. For production environments, it is recommended to update the `ldap3.Tls` configuration to validate your server certificates.

## 📄 License
This project is licensed under the MIT License.

---

**Tip:** If you plan to add more server types, you can simply extend the `SERVER_TYPES` dictionary inside the class!