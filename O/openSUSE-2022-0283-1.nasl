#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0283-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157325);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id(
    "CVE-2020-27840",
    "CVE-2021-20277",
    "CVE-2021-20316",
    "CVE-2021-36222",
    "CVE-2021-43566",
    "CVE-2021-44141",
    "CVE-2021-44142",
    "CVE-2022-0336"
  );
  script_xref(name:"IAVA", value:"2021-A-0140-S");
  script_xref(name:"IAVA", value:"2021-A-0487");
  script_xref(name:"IAVA", value:"2022-A-0020-S");
  script_xref(name:"IAVA", value:"2022-A-0054-S");
  script_xref(name:"IAVB", value:"2021-B-0054-S");

  script_name(english:"openSUSE 15 Security Update : samba (openSUSE-SU-2022:0283-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0283-1 advisory.

  - A flaw was found in samba. Spaces used in a string around a domain name (DN), while supposed to be
    ignored, can cause invalid DN strings with spaces to instead write a zero-byte into out-of-bounds memory,
    resulting in a crash. The highest threat from this vulnerability is to system availability.
    (CVE-2020-27840)

  - A flaw was found in Samba's libldb. Multiple, consecutive leading spaces in an LDAP attribute can lead to
    an out-of-bounds memory write, leading to a crash of the LDAP server process handling the request. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20277)

  - ec_verify in kdc/kdc_preauth_ec.c in the Key Distribution Center (KDC) in MIT Kerberos 5 (aka krb5) before
    1.18.4 and 1.19.x before 1.19.2 allows remote attackers to cause a NULL pointer dereference and daemon
    crash. This occurs because a return value is not properly managed in a certain situation. (CVE-2021-36222)

  - All versions of Samba prior to 4.13.16 are vulnerable to a malicious client using an SMB1 or NFS race to
    allow a directory to be created in an area of the server file system not exported under the share
    definition. Note that SMB1 has to be enabled, or the share also available via NFS in order for this attack
    to succeed. (CVE-2021-43566)

  - All versions of Samba prior to 4.15.5 are vulnerable to a malicious client using a server symlink to
    determine if a file or directory exists in an area of the server file system not exported under the share
    definition. SMB1 with unix extensions has to be enabled in order for this attack to succeed. Clients that
    have write access to the exported part of the file system under a share via SMB1 unix extensions or via
    NFS can create symlinks that point to arbitrary files or directories on the server filesystem. Clients can
    then use SMB1 unix extension information queries to determine if the target of the symlink exists or not
    by examining error codes returned from the smbd server. There is no ability to access these files or
    directories, only to determine if they exist or not. If SMB1 is turned off and only SMB2 is used, or unix
    extensions are not enabled then there is no way to discover if a symlink points to a valid target or not
    via SMB2. For this reason, even if symlinks are created via NFS, if the Samba server does not allow SMB1
    with unix extensions there is no way to exploit this bug. Finding out what files or directories exist on a
    file server can help attackers guess system user names or the exact operating system release and
    applications running on the server hosting Samba which may help mount further attacks. SMB1 has been
    disabled on Samba since version 4.11.0 and onwards. Exploitation of this bug has not been seen in the
    wild. (CVE-2021-44141)

  - samba: Out-of-bounds heap read/write vulnerability in VFS module vfs_fruit allows code execution
    (CVE-2021-44142)

  - The Samba AD DC includes checks when adding service principals names (SPNs) to an account to ensure that
    SPNs do not alias with those already in the database. Some of these checks are able to be bypassed if an
    account modification re-adds an SPN that was previously present on that account, such as one added when a
    computer is joined to a domain. An attacker who has the ability to write to an account can exploit this to
    perform a denial-of-service attack by adding an SPN that matches an existing service. Additionally, an
    attacker who can intercept traffic can impersonate existing services, resulting in a loss of
    confidentiality and integrity. (CVE-2022-0336)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1139519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195048");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/72ZRNFZ3DE3TJA7HFCVV476YJN6I4B5M/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dafccda9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20277");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20316");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-36222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0336");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44142");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0336");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-abstractions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-parser-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-profiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apparmor-utils-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-kdb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-plugin-preauth-spake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libapparmor1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnfsidmap-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_certmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_simpleifp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtalloc2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtdb1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_apparmor-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldb-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-sss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-sssd-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-talloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-talloc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-talloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tdb-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tevent-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-64bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-devel-32bit");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-wbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-wbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:talloc-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tdb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tevent-man");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'apache2-mod_apparmor-2.13.6-150300.3.11.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apparmor-abstractions-2.13.6-150300.3.11.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apparmor-parser-2.13.6-150300.3.11.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apparmor-parser-lang-2.13.6-150300.3.11.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apparmor-profiles-2.13.6-150300.3.11.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apparmor-utils-2.13.6-150300.3.11.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'apparmor-utils-lang-2.13.6-150300.3.11.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ctdb-pcp-pmda-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-1.19.2-150300.8.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-32bit-1.19.2-150300.8.3.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-client-1.19.2-150300.8.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-devel-1.19.2-150300.8.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-devel-32bit-1.19.2-150300.8.3.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-mini-1.19.2-150300.8.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-mini-devel-1.19.2-150300.8.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-plugin-kdb-ldap-1.19.2-150300.8.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-plugin-preauth-otp-1.19.2-150300.8.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-plugin-preauth-pkinit-1.19.2-150300.8.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-plugin-preauth-spake-1.19.2-150300.8.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-1.19.2-150300.8.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ldb-tools-2.4.1-150300.3.10.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libapparmor-devel-2.13.6-150300.3.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libapparmor1-2.13.6-150300.3.11.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libapparmor1-32bit-2.13.6-150300.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac0-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libldb-devel-2.4.1-150300.3.10.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libldb2-2.4.1-150300.3.10.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libldb2-32bit-2.4.1-150300.3.10.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnfsidmap-sss-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy-devel-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy-python3-devel-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy0-python3-32bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy0-python3-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsamba-policy0-python3-64bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-devel-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap0-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap0-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap0-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-devel-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp0-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtalloc-devel-2.3.3-150300.3.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtalloc2-2.3.3-150300.3.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtalloc2-32bit-2.3.3-150300.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtdb-devel-1.4.4-150300.3.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtdb1-1.4.4-150300.3.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtdb1-32bit-1.4.4-150300.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent-devel-0.11.0-150300.3.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent0-0.11.0-150300.3.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtevent0-32bit-0.11.0-150300.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pam_apparmor-2.13.6-150300.3.11.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pam_apparmor-32bit-2.13.6-150300.3.11.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-apparmor-2.13.6-150300.3.11.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-apparmor-2.13.6-150300.3.11.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipa_hbac-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ldb-2.4.1-150300.3.10.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ldb-32bit-2.4.1-150300.3.10.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ldb-devel-2.4.1-150300.3.10.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss-murmur-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sss_nss_idmap-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-sssd-config-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-talloc-2.3.3-150300.3.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-talloc-32bit-2.3.3-150300.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-talloc-devel-2.3.3-150300.3.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-tdb-1.4.4-150300.3.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-tdb-32bit-1.4.4-150300.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-tevent-0.11.0-150300.3.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-tevent-32bit-0.11.0-150300.3.3.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-apparmor-2.13.6-150300.3.11.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ad-dc-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ad-dc-libs-32bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ad-dc-libs-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ceph-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ceph-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-32bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-64bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-32bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-devel-32bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-devel-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-dsdb-modules-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-gpupdate-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-ldb-ldap-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-32bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-64bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-python3-32bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-python3-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-python3-64bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'aarch64_ilp32', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-python3-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-tool-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-libs-32bit-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-libs-4.15.4+git.324.8332acf1a63-150300.3.25.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-wbclient-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-wbclient-devel-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-winbind-idmap-1.16.1-150300.23.17.3', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'talloc-man-2.3.3-150300.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tdb-tools-1.4.4-150300.3.3.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tevent-man-0.11.0-150300.3.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2-mod_apparmor / apparmor-abstractions / apparmor-parser / etc');
}
