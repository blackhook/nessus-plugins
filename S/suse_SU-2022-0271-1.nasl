#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0271-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157315);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2021-44142");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0271-1");
  script_xref(name:"IAVA", value:"2022-A-0054-S");

  script_name(english:"SUSE SLES12 Security Update : samba (SUSE-SU-2022:0271-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2022:0271-1 advisory.

  - The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide ...enhanced compatibility
    with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver. Samba versions prior to
    4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via
    specially crafted extended file attributes. A remote attacker with write access to extended file
    attributes can execute arbitrary code with the privileges of smbd, typically root. (CVE-2021-44142)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194859");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-February/010159.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fd62134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44142");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44142");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-32bit");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libdcerpc-binding0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libdcerpc-binding0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libdcerpc0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libdcerpc0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libndr-krb5pac0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libndr-krb5pac0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libndr-nbt0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libndr-nbt0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libndr-standard0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libndr-standard0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libndr0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libndr0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libnetapi0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libnetapi0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamba-credentials0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamba-credentials0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamba-errors0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamba-errors0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamba-hostconfig0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamba-hostconfig0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamba-passdb0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamba-passdb0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamba-util0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamba-util0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamdb0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsamdb0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsmbclient0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsmbclient0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsmbconf0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsmbconf0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsmbldap0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libsmbldap0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libtevent-util0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libtevent-util0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libwbclient0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libwbclient0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'samba-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'samba-client-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'samba-client-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'samba-doc-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'samba-libs-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'samba-libs-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'samba-winbind-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'samba-winbind-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'libdcerpc-binding0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libdcerpc-binding0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libdcerpc0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libdcerpc0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libndr-krb5pac0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libndr-krb5pac0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libndr-nbt0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libndr-nbt0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libndr-standard0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libndr-standard0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libndr0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libndr0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libnetapi0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libnetapi0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamba-credentials0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamba-credentials0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamba-errors0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamba-errors0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamba-hostconfig0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamba-hostconfig0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamba-passdb0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamba-passdb0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamba-util0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamba-util0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamdb0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsamdb0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsmbclient0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsmbclient0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsmbconf0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsmbconf0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsmbldap0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libsmbldap0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libtevent-util0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libtevent-util0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libwbclient0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'libwbclient0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'samba-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'samba-client-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'samba-client-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'samba-doc-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'samba-libs-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'samba-libs-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'samba-winbind-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'samba-winbind-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'ctdb-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.3']},
    {'reference':'ctdb-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.4']},
    {'reference':'libdcerpc-binding0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libdcerpc-binding0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libdcerpc0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libdcerpc0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libndr-krb5pac0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libndr-krb5pac0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libndr-nbt0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libndr-nbt0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libndr-standard0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libndr-standard0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libndr0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libndr0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libnetapi0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libnetapi0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamba-credentials0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamba-credentials0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamba-errors0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamba-errors0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamba-hostconfig0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamba-hostconfig0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamba-passdb0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamba-passdb0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamba-util0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamba-util0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamdb0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsamdb0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsmbclient0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsmbclient0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsmbconf0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsmbconf0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsmbldap0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libsmbldap0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libtevent-util0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libtevent-util0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libwbclient0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libwbclient0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'samba-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'samba-client-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'samba-client-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'samba-doc-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'samba-libs-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'samba-libs-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'samba-winbind-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'samba-winbind-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'libdcerpc-binding0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libdcerpc-binding0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libdcerpc0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libdcerpc0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libndr-krb5pac0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libndr-krb5pac0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libndr-nbt0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libndr-nbt0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libndr-standard0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libndr-standard0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libndr0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libndr0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libnetapi0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libnetapi0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamba-credentials0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamba-credentials0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamba-errors0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamba-errors0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamba-hostconfig0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamba-hostconfig0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamba-passdb0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamba-passdb0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamba-util0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamba-util0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamdb0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsamdb0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsmbclient0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsmbclient0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsmbconf0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsmbconf0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsmbldap0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libsmbldap0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libtevent-util0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libtevent-util0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libwbclient0-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'libwbclient0-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'samba-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'samba-client-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'samba-client-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'samba-doc-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'samba-libs-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'samba-libs-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'samba-winbind-32bit-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'samba-winbind-4.6.16+git.320.a2d80a7efef-3.70.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libdcerpc-binding0 / libdcerpc-binding0-32bit / libdcerpc0 / etc');
}
