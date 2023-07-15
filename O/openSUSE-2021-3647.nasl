#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3647-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155177);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id(
    "CVE-2016-2124",
    "CVE-2020-25717",
    "CVE-2020-25718",
    "CVE-2020-25719",
    "CVE-2020-25721",
    "CVE-2020-25722",
    "CVE-2021-3738",
    "CVE-2021-23192"
  );
  script_xref(name:"IAVA", value:"2021-A-0554-S");

  script_name(english:"openSUSE 15 Security Update : samba and ldb (openSUSE-SU-2021:3647-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3647-1 advisory.

  - An attacker can downgrade a negotiated SMB1 client connection and its capabitilities. Kerberos
    authentication is only possible with the SMB2/3 protocol or SMB1 using the NT1 dialect and the extended
    security (spnego) capability. Without mandatory SMB signing the protocol can be downgraded to an older
    insecure dialect like CORE, COREPLUS/CORE+, LANMAN1 or LANMAN2. Even if SMB signing is required it's still
    possible to downgrade to the NT1 dialect if extended security (spnego) is not negotiated. The attacker is
    able to get the plaintext password sent over the wire even if Kerberos authentication was required. The
    problem is only possible if all of the following options are explicitly set together: client NTLMv2 auth =
    no client lanman auth = yes client plaintext auth = yes client min protocol = NT1 # or lower In currently
    supported Samba versions all of the above options have different default values, so the problem is very
    unlikely to happen. Samba 4.5 and older had an additional problem, even in the default configuration, as
    they send ntlmv2, ntlm or lanman responses. Which means the attacker might be able to do offline attacks
    in order to recover the plaintext password, lmhash or nthash values. Requiring Kerberos authentication for
    SMB1/2/3 connections can be controlled by the '-k'/'--kerberos' or '-k yes'/'--kerberos=yes' command line
    options of various tools like: smbclient, smbcquotas, smbcacls, net, rpcclient, samba-tool and others.
    Note that 4.15 deprecated '-k/--kerberos*' and introduced '--use-kerberos=required' command line option as
    well as the smb.conf option client use kerberos = required. For libsmbclient based applications the
    usage of Kerberos is controlled by the following function calls: smbc_setOptionUseKerberos(),
    smbc_setOptionFallbackAfterKerberos() and smbc_setOptionNoAutoAnonymousLogin(). (CVE-2016-2124)

  - Windows Active Directory (AD) domains have by default a feature to allow users to create computer
    accounts, controlled by ms-DS-MachineAccountQuota. In addition some (presumably trusted) users have the
    right to create new users or computers in both Samba and Windows Active Directory Domains. These features
    can be quite dangerous in the wrong hands, as the user who creates such accounts has broad privileges to
    not just create them and set their passwords, but to rename them at a later time with the only contraint
    being they may not match an existing samAccountName in AD. When Samba as an AD Domain member accepts a
    Kerberos ticket, it must map the information found therein to a local UNIX user-id (uid). This is
    currently done via the account name in the Active Directory generated Kerberos Privileged Attribute
    Certificate (PAC), or the account name in the ticket (if there is no PAC). For example, Samba will attempt
    to find a user DOMAIN\user before falling back to trying to find the user user. If the DOMAIN\user
    lookup can be made to fail, then a privilege escalation is possible. The easiest example to illustrate
    this is if an attacker creates an account named root (by renaming a MachineAccountQuota based machine
    account), and asks for a login without a Kerberos PAC. Between obtaining the ticket and presenting it to a
    server, the attacker renames the user account to a different name. Samba attempts to look up
    DOMAIN\root, which fails (as this no longer exists) and then falls back to looking up user root, which
    will map to the privileged UNIX uid of 0. This patch changes Samba to require a PAC (in all scenarios
    related to active directory domains) and use the SID and account name values of the PAC, which means the
    combination represents the same point in time. The processing is now similar to as with NTLM based logins.
    The SID is unique and non-repeating and so can't be confused with another user. Additionally, a new
    parameter has been added min domain uid (default 1000), and no matter how we obtain the UNIX uid to use
    in the process token (we may eventually read /etc/passwd or similar), by default no UNIX uid below this
    value will be accepted. The patch also removes the fallback from 'DOMAIN\user' to just 'user', as it
    dangerous and not needed when nss_winbind is used (even when 'winbind use default domain = yes' is set).
    However there are setups which are joined to an active directory domain just for authentication, but the
    authorization is handled without nss_winbind by mapping the domain account to a local user provided by
    nss_file, nss_ldap or something similar. NOTE: These setups won't work anymore without explicitly mapping
    the users! For these setups administrators need to use the 'username map' or 'username map script' option
    in order to map domain users explicitly to local users, e.g. user = DOMAIN\user Please consult 'man 5
    smb.conf' for further details on 'username map' or 'username map script'. Also note that in the above
    example '\' refers to the default value of the 'winbind separator' option. (CVE-2020-25717)

  - Samba as an Active Directory Domain Controller is able to support an RODC, which is meant to have minimal
    privileges in a domain. However, in accepting a ticket from a Samba or Windows RODC, Samba was not
    confirming that the RODC is authorized to print such a ticket, via the msDS-NeverRevealGroup and msDS-
    RevealOnDemandGroup (typically Allowed RODC Replication Group and Denied RODC Replciation Group). This
    would allow an RODC to print administrator tickets. (CVE-2020-25718)

  - Samba as an Active Directory Domain Controller is based on Kerberos, which provides name-based
    authentication. These names are often then used for authorization. However Microsoft Windows and Active
    Direcory is SID-based. SIDs in Windows, similar to UIDs in Linux/Unix (if managed well) are globally
    unique and survive name changes. At the meeting of these two authorization schemes it is possible to
    confuse a server into acting as one user when holding a ticket for another. A Kerberos ticket, once
    issued, may be valid for some time, often 10 hours but potentially longer. In Active Directory, it may or
    may not carry a PAC, holding the user's SIDs. A simple example of the problem is on Samba's LDAP server,
    which would, unless gensec:require_pac = true was set, permit a fall back to using the name in the
    Kerberos ticket alone. (All Samba AD services fall to the same issue in one way or another, LDAP is just a
    good example). Delegated administrators with the right to create other user or machine accounts can abuse
    the race between the time of ticket issue and the time of presentation (back to the AD DC) to impersonate
    a different account, including a highly privileged account. This could allow total domain compromise.
    (CVE-2020-25719)

  - In order to avoid issues like CVE-2020-25717 AD Kerberos accepting services need access to unique, and
    ideally long-term stable identifiers of a user to perform authorization. The AD PAC provides this, but the
    most useful information is kept in a buffer which is NDR encoded, which means that so far in Free Software
    only Samba and applications which use Samba components under the hood like FreeIPA and SSSD decode PAC.
    Recognising that the issues seen in Samba are not unique, Samba now provides an extension to UPN_DNS_INFO,
    a component of the AD PAC, in a way that can be parsed using basic pointer handling. From this, future
    non-Samba based Kerberised applications can easily obtain the user's SID, in the same packing as objectSID
    in LDAP, confident that the ticket represents a specific user, not matter subsequent renames. This will
    allow such non-Samba applications to avoid confusing one Kerberos user for another, even if they have the
    same string name (due to the gap between time of ticket printing by the KDC and time of ticket
    acceptance). The protocol deployment weakness, as demonstrated with the CVE-2020-25717 in Samba when
    deployed in Active Directory, leaves most Linux and UNIX applications only to rely on the client name
    from the Kerberos ticket. When the client name as seen by the KDC is under an attacker control across
    multiple Kerberos requests, such applications need an additional information to correlate the client name
    across those requests. Directories where only full administrators can create users are not the concern,
    the concern is where that user/computer creation right is delegated in some way, explicitly or via ms-DS-
    MachineAccountQuota. (CVE-2020-25721)

  - Samba as an Active Directory Domain Controller has to take care to protect a number of sensitive
    attributes, and to follow a security model from Active Directory that relies totally on the intersection
    of NT security descriptors and the underlying X.500 Directory Access Protocol (as then expressed in LDAP)
    schema constraints for security. Some attributes in Samba AD are sensitive, they apply to one object but
    protect others. Users who can set msDS-AllowedToDelegateTo can become any user in the domain on the server
    pointed at by this list. Likewise in a domain mixed with Microsoft Windows, Samba's lack of protection of
    sidHistory would be a similar issue. This would be limited to users with the right to create users or
    modify them (typically those who created them), however, due to other flaws, all users are able to create
    new user objects. Finally, Samba did not enforce userPrincipalName and servicePrincipalName uniqueness,
    nor did it correctly implement the validated SPN feature allowing machine accounts to safely set their
    own SPN (the checks were easily bypassed and additionally should have been restricted to
    objectClass=computer). Samba has implemented this feature, which avoids a denial of service (UPNs) or
    service impersonation (SPNs) between users privileged to add users to the domian (but see the above
    point). This release adds a feature similar in goal but broader in implementation than that found in the
    Windows 2012 Forest Functional level. (CVE-2020-25722)

  - Samba implements DCE/RPC, and in most cases it is provided over and protected by the underlying SMB
    transport, with protections like 'SMB signing'. However there are other cases where large DCE/RPC request
    payloads are exchanged and fragmented into several pieces. If this happens over untrusted transports (e.g.
    directly over TCP/IP or anonymous SMB) clients will typically protect by an explicit authentication at the
    DCE/RPC layer, e.g. with GSSAPI/Kerberos/NTLMSSP or Netlogon Secure Channel. Because the checks on the
    fragment protection were not done between the policy controls on the header and the subsequent fragments,
    an attacker could replace subsequent fragments in requests with their own data, which might be able to
    alter the server behaviour. DCE/RPC is a core component of all Samba servers, but we are most concerned
    about Samba as a Domain Controller, given the role as a centrally trusted service. As active directory
    domain controller this issue affects Samba versions greater or equal to 4.10.0. As NT4 classic domain
    controller, domain member or standalone server this issue affects Samba versions greater or equal to
    4.13.0. (CVE-2021-23192)

  - In DCE/RPC it is possible to share the handles (cookies for resource state) between multiple connections
    via a mechanism called 'association groups'. These handles can reference connections to our sam.ldb
    database. However while the database was correctly shared, the user credentials state was only pointed at,
    and when one connection within that association group ended, the database would be left pointing at an
    invalid 'struct session_info'. The most likely outcome here is a crash, but it is possible that the use-
    after-free could instead allow different user state to be pointed at and this might allow more privileged
    access. (CVE-2021-3738)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1014440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192215");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192505");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/36K5HNX67LYX5XOVQRL3MSIC5YSJ5M5W/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ab8e9a2");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-2124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25719");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25721");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25722");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3738");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25719");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr1-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap2-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldb-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-gpupdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ldb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python3-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-64bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'ctdb-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-pcp-pmda-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-tests-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ldb-tools-2.2.2-3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-binding0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-binding0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-binding0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-samr-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-samr0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-samr0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-samr0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libldb-devel-2.2.2-3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libldb2-2.2.2-3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libldb2-32bit-2.2.2-3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-krb5pac-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-krb5pac0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-krb5pac0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-krb5pac0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-nbt-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-nbt0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-nbt0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-nbt0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-standard-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-standard0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-standard0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-standard0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr1-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr1-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr1-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-devel-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-devel-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-credentials-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-credentials0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-credentials0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-credentials0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-errors-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-errors0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-errors0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-errors0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-hostconfig-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-hostconfig0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-hostconfig0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-hostconfig0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-passdb-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-passdb0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-passdb0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-passdb0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy-python3-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy0-python3-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy0-python3-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy0-python3-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-util-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-util0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-util0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-util0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamdb-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamdb0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamdb0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamdb0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbconf-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbconf0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbconf0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbconf0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbldap-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbldap2-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbldap2-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbldap2-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent-util-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent-util0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent-util0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent-util0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient0-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient0-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient0-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ldb-2.2.2-3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ldb-32bit-2.2.2-3.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ldb-devel-2.2.2-3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ad-dc-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ad-dc-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ad-dc-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ceph-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ceph-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-core-devel-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dsdb-modules-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-gpupdate-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ldb-ldap-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-python3-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-python3-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-python3-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-python3-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-32bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.13.13+git.528.140935f8d6a-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-64bit-4.13.13+git.528.140935f8d6a-3.12.1', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / ctdb-pcp-pmda / ctdb-tests / ldb-tools / libdcerpc-binding0 / etc');
}
