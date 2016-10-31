from pprint import pprint
from urllib.parse import urlparse
from ldap3 import Server, Connection, SIMPLE, SYNC, ASYNC, SUBTREE, ALL, MODIFY_ADD, MODIFY_DELETE
from configparser import ConfigParser
import os.path


config = ConfigParser()
config.read(['/etc/syzacz.conf', 'syzacz.conf', os.path.join(os.path.dirname(__file__), '../syzacz.conf')])


class Session:
    def __init__(self):
        self.config = config
        self.ldap_config = self.config['ldap']

        url = urlparse(self.ldap_config.get('url'))

        self.server = Server(url.hostname, port=url.port, get_info=ALL)
        self.connection = Connection(self.server, auto_bind=True, client_strategy=SYNC,
                                     user=self.ldap_config.get('bind_dn'), password=self.ldap_config.get('passwd'),
                                     authentication=SIMPLE, check_names=True)

    def close(self):
        self.connection.unbind()

    def get_simple(self, search_base, attributes, search_filter=None, flaten=None):
        search_filter = search_filter or '(objectClass=*)'

        if flaten is False:
            flaten = []
        else:
            flaten = flaten or ['cn', 'uid']

        entries = self.connection.extend.standard.paged_search(search_base=search_base,
                                                               search_filter=search_filter,
                                                               search_scope=SUBTREE,
                                                               attributes=attributes,
                                                               paged_size=10,
                                                               generator=True)

        results = []

        for entry in entries:
            if len(entry['attributes']) == 0:
                continue

            result = entry['attributes']
            result['dn'] = entry['dn']

            for attribute_name in result:
                if attribute_name in flaten:
                    result[attribute_name] = result[attribute_name][0]

            results.append(result)

        return results

    def get_groups(self, attributes=None):
        attributes = attributes or ['cn', 'gidNumber', 'description']
        return self.get_simple(search_base=self.ldap_config.get('group_ou'),
                               attributes=attributes)

    def get_users(self, attributes=None):
        attributes = attributes or ['uid', 'cn', 'mail']

        casual = list(attributes)
        casual.remove('groups')

        users = self.get_simple(search_base=self.ldap_config.get('user_ou'),
                                attributes=casual)

        if 'groups' in attributes:
            for user in users:
                user['groups'] = [group['cn'] for group in self.get_user_groups(uid=user['uid'])]

        return users

    def get_user_dn(self, uid):
        return 'uid={uid},{user_ou}'.format(user_ou=self.ldap_config.get('user_ou'), uid=uid)

    def get_group_dn(self, cn):
        return 'cn={cn},{group_ou}'.format(group_ou=self.ldap_config.get('group_ou'), cn=cn)

    def get_user_groups(self, uid, attributes=None):
        user_dn = self.get_user_dn(uid)

        groups = self.get_simple(
            search_base=self.ldap_config.get('group_ou'),
            search_filter='(|(member={dn})(memberUid={uid}))'.format(dn=user_dn, uid=uid),
            attributes=attributes or ['cn'])

        return groups

    def add_user(self, username, common_name, email=None):
        attributes = {'cn': common_name,
                      'sn': common_name.split()[-1],
                      'mail': email}

        self.connection.add(
            dn="uid={username},{user_ou}".format(username=username, user_ou=self.ldap_config.get('user_ou')),
            object_class=['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
            attributes=attributes)

        self.upgrade_user_schema(username=username)

    def get_top_uid(self):
        users = self.get_simple(search_base=self.ldap_config.get('user_ou'),
                                attributes=['uidNumber'])
        return max([user['uidNumber'] for user in users])

    def _migration0(self, username):
        user_dn = self.get_user_dn(uid=username)

        self.connection.modify(
            dn=user_dn,
            changes={
                'objectClass': [(MODIFY_ADD, ['posixAccount'])],
                'loginShell': [(MODIFY_ADD, ['/bin/bash'])],
                'homeDirectory': [(MODIFY_ADD, ['/home/{}'.format(username)])],
                'gidNumber': [(MODIFY_ADD, ['1999'])],
                'uidNumber': [(MODIFY_ADD, [self.get_top_uid() + 1])],
            })

    def upgrade_user_schema(self, username):
        self._migration0(username=username)

    def delete_user(self, username):
        user_dn = self.get_user_dn(uid=username)
        groups = self.get_user_groups(uid=username)

        for group in groups:
            self.delete_from_group(username=username, group=group['cn'])

        self.connection.delete(user_dn)

    def change_password(self, username, password):
        self.connection.extend.standard.modify_password(user=self.get_user_dn(uid=username),
                                                        new_password=password)

    def add_to_group(self, username, group):
        user_dn = self.get_user_dn(uid=username)
        group_dn = self.get_group_dn(cn=group)

        self.connection.modify(dn=group_dn,
                               changes={'member': [(MODIFY_ADD, [user_dn])]})

    def delete_from_group(self, username, group):
        user_dn = self.get_user_dn(uid=username)
        group_dn = self.get_group_dn(cn=group)

        self.connection.modify(dn=group_dn,
                               changes={'member': [(MODIFY_DELETE, [user_dn])]})

    def add_to_groups(self, username, groups):
        for group in groups:
            self.add_to_group(username=username, group=group)

    def delete_from_groups(self, username, groups):
        for group in groups:
            self.delete_from_group(username=username, group=group)

    def activate(self, username):
        self.add_to_group(username=username, group='members')

    def deactivate(self, username):
        self.delete_from_group(username=username, group='members')
