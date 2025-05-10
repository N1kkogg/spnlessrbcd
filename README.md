# Abusing Kerberos Resource-Based Constrained Delegation As a normal user without a SPN 

## Description
This script is a slightly modified version of RBCD.py script from the impacket collection (https://github.com/fortra/impacket), providing additional support for exploiting rbcd (msDS-AllowedToActOnBehalfOfOtherIdentity property exploitation) as a normal user without a SPN, which was demonstrated in 2022 by Jame Forshaw. This script heavily relies in rbcd.py and features some code from snovvcrash's smbpasswd.py.


The technique is as follows (from https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users):


1 -Obtain a TGT for the SPN-less user allowed to delegate to a target and retrieve the TGT session key.

2 - Change the user's password hash and set it to the TGT session key.

3 - Combine S4U2self and U2U so that the SPN-less user can obtain a service ticket to itself, on behalf of another (powerful) user, and then proceed to S4U2proxy to obtain a service ticket to the target the user can delegate to, on behalf of the other, more powerful, user.

4 - Pass the ticket and access the target, as the delegated other
    
## Example Usage:
`python3 spnlessrbcd.py -action write -delegate-to "DC$" -delegate-from "j.doe" -dc-ip 10.10.13.37 -hashes :126502da14a98b58f2c319b81b3a49cb -spnless contoso.local/j.doe -debug`

*note the -spnless option*

## References:
https://github.com/fortra/impacket/blob/master/examples/rbcd.py
https://github.com/snovvcrash/impacket/blob/master/examples/smbpasswd.py
https://twitter.com/tiraniddo
https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users
