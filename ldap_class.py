import ldap3
import ssl
import random
import string
import re

class LDAPManager:
    SERVER_TYPES = {
        'ad': {
            'user_filter': '(&(objectClass=user)(objectCategory=person))',
            'user_id': 'sAMAccountName',
            'user_classes': ['top', 'person', 'organizationalPerson', 'user'],
        },
        'openldap': {
            'user_filter': '(objectClass=inetOrgPerson)',
            'user_id': 'uid',
            'user_classes': ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
        },
        'freeipa': {
            'user_filter': '(objectClass=posixAccount)',
            'user_id': 'uid',
            'user_classes': ['top', 'person', 'organizationalPerson', 'inetOrgPerson', 'posixAccount'],
        },
    }

    def __init__(self, ldap_address, ldap_port=None, ldap_user='', ldap_password='',
                 connection_type='', domain='', server_type='ad'):
        self.conn = None
        self.domain = domain
        self.ldap_address = ldap_address
        self.ldap_port = ldap_port or (636 if connection_type == 'ssl' else 389)
        self.ldap_user = ldap_user
        self.ldap_password = ldap_password
        self.connection_type = connection_type
        self.server_type = server_type.lower()
        self.cfg = self.SERVER_TYPES.get(self.server_type, self.SERVER_TYPES['ad'])
        print(f'address {self.ldap_address} port {self.ldap_port} ldap_user: {self.ldap_user} connection_type: {self.connection_type} server_type: {self.server_type}')

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.unbind()

    def connect(self):
        try:
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT) if self.connection_type in ('ssl', 'tls') else None
            server = ldap3.Server(host=self.ldap_address, use_ssl=(self.connection_type == 'ssl'), tls=tls, get_info=ldap3.ALL)
            self.conn = ldap3.Connection(server, user=self.ldap_user, password=self.ldap_password, auto_bind=ldap3.AUTO_BIND_NO_TLS, authentication=ldap3.SIMPLE)
            if self.connection_type == 'tls' and not self.conn.start_tls():
                raise Exception("Failed to start TLS")
            print("connect is ok")
            return True
        except Exception as e:
            print(f"Error: {e}")
            return None

    def unbind(self):
        if self.conn and self.conn.bound:
            self.conn.unbind()
            print("unbind is ok")
        else:
            print("already unbind")

    def _search(self, base, filter_, attrs=None):
        self.conn.search(search_base=base, search_filter=filter_, search_scope=ldap3.SUBTREE, attributes=attrs or ['*'])
        return self.conn.entries

    def _get_dn(self, base, filter_):
        entries = self._search(base, filter_, ['distinguishedName'])
        return entries[0].entry_dn if entries else None

    def users_get(self, base_dn=''):
        try:
            entries = self._search(base_dn, self.cfg['user_filter'])
            if not entries:
                print('Error: Empty entries')
                return None
            users = []
            uid = self.cfg['user_id']
            for e in entries:
                dn = e.distinguishedName.value
                uname = e[uid].value if uid in e else dn
                users.append(uname)
                print(f"- {uname} -> : {dn}")
            return users
        except Exception as e:
            print(f"Error: {e}")
            return False

    def user_create(self, username, first_name, last_name, base_dn=''):
        try:
            uid = self.cfg['user_id']
            user_dn = f"CN={first_name} {last_name},{base_dn}" if self.server_type == 'ad' else f"uid={username},{base_dn}"
            attrs = {
                'objectClass': self.cfg['user_classes'],
                uid: username,
                'givenName': first_name,
                'sn': last_name,
                'displayName': f"{first_name} {last_name}",
                'cn': f"{first_name} {last_name}",
            }
            if self.server_type == 'ad':
                attrs['userPrincipalName'] = f"{username}@{self.domain}"
                attrs['name'] = f"{first_name} {last_name}"
            self.conn.add(user_dn, attributes=attrs)
            ok = self.conn.result['result'] == 0
            print(f"{'user_create ok' if ok else 'Error user_create: ' + self.conn.result['description']}")
            return ok
        except Exception as e:
            print(f"Error: {e}")
            return False

    def user_delete(self, username, base_dn=''):
        try:
            uid = self.cfg['user_id']
            user_dn = self._get_dn(base_dn, f"({uid}={ldap3.utils.conv.escape_filter_chars(username)})")
            if not user_dn:
                print('Error: user not found')
                return False
            self.conn.delete(user_dn)
            ok = self.conn.result['result'] == 0
            print(f"{'user_delete ok' if ok else 'Error user_delete: ' + self.conn.result['description']}")
            return ok
        except Exception as e:
            print(f"Error: {e}")
            return False

    def delete_by_dn(self, dn):
        try:
            self.conn.delete(dn)
            ok = self.conn.result['result'] == 0
            print(f"{'dn_delete ok' if ok else 'Error dn_delete: ' + self.conn.result['description']}")
            return ok
        except Exception as e:
            print(f"Error: {e}")
            return False

    def user_state(self, username, state, base_dn=''):
        try:
            if self.server_type != 'ad':
                print("user_state only supported for Active Directory")
                return False
            uid = self.cfg['user_id']
            entries = self._search(base_dn, f"({uid}={ldap3.utils.conv.escape_filter_chars(username)})")
            if not entries:
                print('Error: user not found')
                return False
            user_dn = entries[0].entry_dn
            current_uac = entries[0]['userAccountControl'].value
            ACCOUNT_DISABLED = 0x0002
            new_uac = (current_uac & ~ACCOUNT_DISABLED) if state else (current_uac | ACCOUNT_DISABLED)
            action = 'Enabled' if state else 'Disabled'
            if new_uac != current_uac:
                self.conn.modify(user_dn, {'userAccountControl': [(ldap3.MODIFY_REPLACE, [new_uac])]})
                print(f"user_state: {action} account: {username}")
            else:
                print(f"user_state already {action.lower()}: {username}")
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False

    def user_enable(self, username, base_dn=''):
        return self.user_state(username, True, base_dn)

    def user_disable(self, username, base_dn=''):
        return self.user_state(username, False, base_dn)

    def password_generate(self):
        chars = [random.choice(string.ascii_lowercase), random.choice(string.ascii_uppercase),
                 random.choice(string.digits), random.choice('!#$%&()*+,-./:;<=>?@[\\]^{|}~')]
        chars += [random.choice(string.ascii_letters + string.digits + '!#$%&()*+,-./:;<=>?@[\\]^{|}~') for _ in range(random.randint(4, 11))]
        random.shuffle(chars)
        return ''.join(chars)

    def user_password(self, username, new_password, base_dn=''):
        try:
            uid = self.cfg['user_id']
            user_dn = self._get_dn(base_dn, f"({uid}={ldap3.utils.conv.escape_filter_chars(username)})")
            if not user_dn:
                print('Error: user not found')
                return False
            if self.server_type == 'ad':
                self.conn.extend.microsoft.modify_password(user_dn, new_password)
            else:
                self.conn.modify(user_dn, {'userPassword': [(ldap3.MODIFY_REPLACE, [new_password])]})
            print(f'user {username} - password updated')
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
