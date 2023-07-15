#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3662-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155363);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/28");

  script_cve_id("CVE-2020-25717");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3662-1");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : samba (SUSE-SU-2021:3662-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 host has packages installed that are affected by a vulnerability as referenced in
the SUSE-SU-2021:3662-1 advisory.

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192601");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-November/009724.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f71c442");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25717");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ad-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-gpupdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ldb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + sp);
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'ctdb-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-ha-release-15.3'},
    {'reference':'libdcerpc-binding0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc-binding0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc-binding0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc-binding0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc-samr-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc-samr-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc-samr0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc-samr0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libdcerpc0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-krb5pac-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-krb5pac-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-krb5pac0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-krb5pac0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-krb5pac0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-krb5pac0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-nbt-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-nbt-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-nbt0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-nbt0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-nbt0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-nbt0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-standard-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-standard-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-standard0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-standard0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-standard0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr-standard0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr1-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr1-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr1-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libndr1-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libnetapi-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libnetapi-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libnetapi0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libnetapi0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libnetapi0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libnetapi0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-credentials-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-credentials-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-credentials0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-credentials0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-credentials0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-credentials0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-errors-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-errors-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-errors0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-errors0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-errors0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-errors0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-hostconfig-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-hostconfig-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-hostconfig0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-hostconfig0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-hostconfig0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-hostconfig0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-passdb-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-passdb-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-passdb0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-passdb0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-passdb0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-passdb0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-policy-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-policy-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-policy-python3-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-policy-python3-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-policy0-python3-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-policy0-python3-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-util-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-util-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-util0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-util0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-util0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamba-util0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamdb-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamdb-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamdb0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamdb0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamdb0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsamdb0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbclient-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbclient-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbclient0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbclient0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbconf-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbconf-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbconf0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbconf0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbconf0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbconf0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbldap-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbldap-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbldap2-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbldap2-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbldap2-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libsmbldap2-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libtevent-util-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libtevent-util-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libtevent-util0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libtevent-util0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libtevent-util0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libtevent-util0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libwbclient-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libwbclient-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libwbclient0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libwbclient0-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libwbclient0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'libwbclient0-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-ceph-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-ceph-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-ceph-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-ceph-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-client-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-client-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-core-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-core-devel-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-dsdb-modules-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-dsdb-modules-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-gpupdate-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-gpupdate-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-ldb-ldap-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-ldb-ldap-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-libs-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-libs-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-libs-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-libs-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-libs-python3-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-libs-python3-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-python3-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-python3-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-winbind-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-winbind-32bit-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-winbind-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-winbind-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'samba-ad-dc-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-python2-release-15.3'},
    {'reference':'samba-ad-dc-4.13.13+git.531.903f5c0ccdc-3.17.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-python2-release-15.3'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libdcerpc-binding0 / libdcerpc-binding0-32bit / libdcerpc-devel / etc');
}
