#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1471-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155356);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/28");

  script_cve_id("CVE-2016-2124", "CVE-2020-25717", "CVE-2021-23192");

  script_name(english:"openSUSE 15 Security Update : samba (openSUSE-SU-2021:1471-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1471-1 advisory.

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
    example '\' refers to the default value of the 'winbind separator' option. [Added 2021-11-11] There's
    sadly a regression that allow trusted domains = no prevents winbindd from starting, fixes are available
    at https://bugzilla.samba.org/show_bug.cgi?id=14899 Please also notice the additional fix and advanced
    example for the 'username map [script]' based fallback from 'DOMAIN\user' to 'user'. See
    https://bugzilla.samba.org/show_bug.cgi?id=14901 and https://gitlab.com/samba-
    team/samba/-/merge_requests/2251 (CVE-2020-25717)

  - Subsequent DCE/RPC fragment injection vulnerability [fedora-all] (CVE-2021-23192)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1014440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192284");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6W4QSQCTUGSIZCTRT4FGJNMRLZDUZS6Y/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c2d54bd");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-2124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23192");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25717");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'ctdb-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-pcp-pmda-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-tests-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-binding0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-binding0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-samr-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-samr0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc-samr0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libdcerpc0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-krb5pac-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-krb5pac0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-krb5pac0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-nbt-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-nbt0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-nbt0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-standard-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-standard0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr-standard0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libndr0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-devel-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnetapi0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-credentials-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-credentials0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-credentials0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-errors-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-errors0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-errors0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-hostconfig-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-hostconfig0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-hostconfig0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-passdb-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-passdb0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-passdb0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy-python3-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy0-python3-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy0-python3-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-util-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-util0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-util0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamdb-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamdb0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamdb0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbconf-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbconf0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbconf0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbldap-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbldap2-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbldap2-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent-util-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent-util0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent-util0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient0-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient0-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ad-dc-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ad-dc-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ceph-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-core-devel-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dsdb-modules-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-python3-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-python3-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-python3-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-32bit-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.11.14+git.308.666c63d4eea-lp152.3.28.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / ctdb-pcp-pmda / ctdb-tests / libdcerpc-binding0 / etc');
}
