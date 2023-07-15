#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3650-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155191);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/28");

  script_cve_id("CVE-2016-2124", "CVE-2020-25717", "CVE-2021-23192");

  script_name(english:"openSUSE 15 Security Update : samba (openSUSE-SU-2021:3650-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3650-1 advisory.

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1014440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192284");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7ZU5FWTEOBTHR7WNP3HEICT3NJTBNV2V/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b59ec2d6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-2124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23192");
  script_set_attribute(attribute:"solution", value:
"Update the affected libndr0 and / or libndr0-32bit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25717");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
    {'reference':'libndr0-32bit-4.11.14+git.308.666c63d4eea-4.28.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr0-4.11.14+git.308.666c63d4eea-4.28.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libndr0 / libndr0-32bit');
}
