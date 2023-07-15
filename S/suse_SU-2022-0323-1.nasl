#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0323-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157373);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2020-25721",
    "CVE-2020-29361",
    "CVE-2021-20316",
    "CVE-2021-43566",
    "CVE-2021-44141",
    "CVE-2021-44142",
    "CVE-2022-0336"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0323-1");
  script_xref(name:"IAVA", value:"2022-A-0020-S");
  script_xref(name:"IAVA", value:"2022-A-0054-S");

  script_name(english:"SUSE SLES12 Security Update : samba (SUSE-SU-2022:0323-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0323-1 advisory.

  - Kerberos acceptors need easy access to stable AD identifiers (eg objectSid). Samba as an AD DC now
    provides a way for Linux applications to obtain a reliable SID (and samAccountName) in issued tickets.
    (CVE-2020-25721)

  - An issue was discovered in p11-kit 0.21.1 through 0.23.21. Multiple integer overflows have been discovered
    in the array allocations in the p11-kit library and the p11-kit list command, where overflow checks are
    missing before calling realloc or calloc. (CVE-2020-29361)

  - A flaw was found in the way Samba handled file/directory metadata. This flaw allows an authenticated
    attacker with permissions to read or modify share metadata, to perform this operation outside of the
    share. (CVE-2021-20316)

  - All versions of Samba prior to 4.13.16 are vulnerable to a malicious client using an SMB1 or NFS race to
    allow a directory to be created in an area of the server file system not exported under the share
    definition. Note that SMB1 has to be enabled, or the share also available via NFS in order for this attack
    to succeed. (CVE-2021-43566)

  - All versions of Samba prior to 4.15.5 are vulnerable to a malicious client using a server symlink to
    determine if a file or directory exists in an area of the server file system not exported under the share
    definition. SMB1 with unix extensions has to be enabled in order for this attack to succeed.
    (CVE-2021-44141)

  - The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide ...enhanced compatibility
    with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver. Samba versions prior to
    4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via
    specially crafted extended file attributes. A remote attacker with write access to extended file
    attributes can execute arbitrary code with the privileges of smbd, typically root. (CVE-2021-44142)

  - The Samba AD DC includes checks when adding service principals names (SPNs) to an account to ensure that
    SPNs do not alias with those already in the database. Some of these checks are able to be bypassed if an
    account modification re-adds an SPN that was previously present on that account, such as one added when a
    computer is joined to a domain. An attacker who has the ability to write to an account can exploit this to
    perform a denial-of-service attack by adding an SPN that matches an existing service. Additionally, an
    attacker who can intercept traffic can impersonate existing services, resulting in a loss of
    confidentiality and integrity. (CVE-2022-0336)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1089938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1139519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195048");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-February/010181.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1fe4996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25721");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20316");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apparmor-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apparmor-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apparmor-profiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apparmor-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ca-certificates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libapparmor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libapparmor1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libapparmor1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutls30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutls30-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhogweed4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhogweed4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libipa_hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libp11-kit0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libp11-kit0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_certmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_nss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_simpleifp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit-nss-trust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pam_apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pam_apparmor-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-apparmor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-sssd-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ldb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:yast2-samba-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'apache2-mod_apparmor-2.8.2-56.6.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'apparmor-docs-2.8.2-56.6.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'apparmor-parser-2.8.2-56.6.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'apparmor-profiles-2.8.2-56.6.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'apparmor-utils-2.8.2-56.6.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'ca-certificates-1_201403302107-15.3.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libapparmor-devel-2.8.2-56.6.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libapparmor1-2.8.2-56.6.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libapparmor1-32bit-2.8.2-56.6.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libgnutls30-3.4.17-8.4.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libgnutls30-32bit-3.4.17-8.4.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libhogweed4-3.1-21.3.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libhogweed4-32bit-3.1-21.3.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libipa_hbac-devel-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libipa_hbac0-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libnettle6-3.1-21.3.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libnettle6-32bit-3.1-21.3.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libp11-kit0-0.23.2-8.3.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libp11-kit0-32bit-0.23.2-8.3.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libsamba-policy-devel-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libsamba-policy-python3-devel-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libsamba-policy0-python3-32bit-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libsamba-policy0-python3-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libsss_certmap0-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libsss_idmap-devel-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libsss_idmap0-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libsss_nss_idmap-devel-1.16.1-7.28.9', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libsss_nss_idmap-devel-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libsss_nss_idmap0-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'libsss_simpleifp0-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'p11-kit-0.23.2-8.3.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'p11-kit-32bit-0.23.2-8.3.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'p11-kit-devel-0.23.2-8.3.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'p11-kit-nss-trust-0.23.2-8.3.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'p11-kit-tools-0.23.2-8.3.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'pam_apparmor-2.8.2-56.6.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'pam_apparmor-32bit-2.8.2-56.6.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'perl-apparmor-2.8.2-56.6.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'python-sssd-config-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-client-32bit-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-client-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-client-libs-32bit-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-client-libs-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-devel-32bit-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-devel-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-devel-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-doc-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-ldb-ldap-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-libs-32bit-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-libs-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-libs-python3-32bit-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-libs-python3-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-python3-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-tool-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-winbind-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-winbind-libs-32bit-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'samba-winbind-libs-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'sssd-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'sssd-ad-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'sssd-common-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'sssd-dbus-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'sssd-ipa-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'sssd-krb5-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'sssd-krb5-common-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'sssd-ldap-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'sssd-proxy-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'sssd-tools-1.16.1-7.28.9', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'yast2-samba-client-3.1.23-3.3.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'ctdb-4.15.4+git.324.8332acf1a63-3.54.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2-mod_apparmor / apparmor-docs / apparmor-parser / etc');
}
