from pprint import pprint
from urllib.parse import urlparse
from ldap3 import Server, Connection, SIMPLE, SYNC, ASYNC, SUBTREE, ALL, MODIFY_ADD, MODIFY_DELETE
from configparser import ConfigParser
from prettytable import PrettyTable
import os.path


config = ConfigParser()
config.read(['/etc/syzacz.conf', 'syzacz.conf', os.path.join(os.path.dirname(__file__), '../syzacz.conf')])


class Session:
    def __init__(self):
        self.config = config
        self.ldap_config = self.config['ldap']

        url = urlparse(self.ldap_config.get('url'))

        # define the server and the connection
        self.server = Server(url.hostname, port=url.port, get_info=ALL)
        self.connection = Connection(self.server, auto_bind=True, client_strategy=SYNC,
                                     user=self.ldap_config.get('bind_dn'), password=self.ldap_config.get('passwd'),
                                     authentication=SIMPLE, check_names=True)

    def close(self):
        self.connection.unbind()

    def query_table(self, search_base, search_filter, fields):
        print(search_filter)
        t = PrettyTable(fields)

        for field in fields:
            t.align[field] = "l"

        entries = self.connection.extend.standard.paged_search(search_base=search_base,
                                                               search_filter=search_filter,
                                                               search_scope=SUBTREE,
                                                               attributes=fields,
                                                               paged_size=10,
                                                               generator=True)

        for entry in entries:
            if len(entry['attributes']) <= 0:
                continue

            f = []

            for field in fields:
                if field in entry['attributes']:
                    f.append(', '.join(entry['attributes'][field]))
                else:
                    f.append('---')

            t.add_row(f)

        return str(t)

    def query_debug(self, search_base, search_filter, *args, **kwargs):
        self.connection.search(search_base=search_base,
                               search_filter=search_filter,
                               search_scope=SUBTREE)
        response = self.connection.response
        result = self.connection.result
        for r in response:
            print(r['dn'], r['attributes'])  # return formatted attributes
            # print(r['dn'], r['raw_attributes'])  # return raw (bytes) attributes
        print(result)

    def list_members(self):
        return self.query_table(search_base=self.ldap_config.get('user_ou'),
                                search_filter="(&(objectClass=*)(memberof=cn=members,{group_ou}))".format(group_ou=self.ldap_config.get('group_ou')),
                                fields=["uid", "cn", "mail"])

    def list_users(self):
        search_base = self.ldap_config.get('user_ou')
        search_filter = '(objectClass=*)'
        fields = ["uid", "cn", "mail"]

        t = PrettyTable(fields + ['groups'])

        for field in fields:
            t.align[field] = 'l'
        t.align['groups'] = 'l'

        entries = self.connection.extend.standard.paged_search(search_base=search_base,
                                                               search_filter=search_filter,
                                                               search_scope=SUBTREE,
                                                               attributes=fields,
                                                               paged_size=10,
                                                               generator=True)

        for entry in entries:
            if len(entry['attributes']) <= 0:
                continue

            f = []

            for field in fields:
                if field in entry['attributes']:
                    f.append(', '.join(entry['attributes'][field]))
                else:
                    f.append('---')

            self.connection.search(search_base=self.ldap_config.get('group_ou'),
                                   search_filter='(&(objectClass=*)(member={dn}))'.format(dn=entry['dn']),
                                   search_scope=SUBTREE,
                                   attributes=['cn'])

            g_response = self.connection.response
            groups = [', '.join(gentry['attributes']['cn']) for gentry in g_response]
            f.append(', '.join(groups))

            t.add_row(f)

        return str(t)

    def add_user(self, username, common_name, email=None):
        attributes = {'cn': common_name,
                      'sn': common_name.split()[-1],
                      'mail': email}
        self.connection.add(dn="uid={username},{user_ou}".format(username=username, user_ou=self.ldap_config.get('user_ou')),
                            object_class=['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
                            attributes=attributes)

        print(self.connection.result)

        return self.connection.result['description'] == 'success'

    def change_password(self, username, password):
        self.connection.extend.standard.modify_password(user="uid={username},{user_ou}".format(username=username, user_ou=self.ldap_config.get('user_ou')),
                                                        new_password=password)

    def add_to_group(self, username, group):
        user_dn = "uid={username},{user_ou}".format(username=username, user_ou=self.ldap_config.get('user_ou'))
        self.connection.modify(dn="cn={group_name},{group_ou}".format(group_name=group, group_ou=self.ldap_config.get('group_ou')),
                               changes={'member': [(MODIFY_ADD, [user_dn])]})

    def delete_from_group(self, username, group):
        user_dn = "uid={username},{user_ou}".format(username=username, user_ou=self.ldap_config.get('user_ou'))
        self.connection.modify(dn="cn={group_name},{group_ou}".format(group_name=group, group_ou=self.ldap_config.get('group_ou')),
                               changes={'member': [(MODIFY_DELETE, [user_dn])]})

    def activate(self, username):
        self.add_to_group(username=username, group='members')

    def deactivate(self, username):
        self.delete_from_group(username=username, group='members')

    def xmpp_activate(self, username):
        self.add_to_group(username=username, group='xmpp')

    def xmpp_deactivate(self, username):
        self.delete_from_group(username=username, group='xmpp')

    def staff_activate(self, username):
        self.add_to_group(username=username, group='staff')

    def staff_deactivate(self, username):
        self.delete_from_group(username=username, group='staff')

    def admin_activate(self, username):
        self.add_to_group(username=username, group='admin')

    def admin_deactivate(self, username):
        self.delete_from_group(username=username, group='admin')
