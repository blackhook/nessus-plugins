#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:2407-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151877);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-36385",
    "CVE-2021-3609",
    "CVE-2021-3612",
    "CVE-2021-22555",
    "CVE-2021-33909"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:2407-1");
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2021:2407-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:2407-1 advisory.

  - An issue was discovered in the Linux kernel before 5.10. drivers/infiniband/core/ucma.c has a use-after-
    free because the ctx is reached via the ctx_list in some ucma_migrate_id situations where ucma_close is
    called, aka CID-f5449e74802c. (CVE-2020-36385)

  - A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c.
    This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name
    space (CVE-2021-22555)

  - fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer
    allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an
    unprivileged user, aka CID-8cae8cd89f05. (CVE-2021-33909)

  - To fix this vulnerability, update the affected packages: linux linux-esx (CVE-2021-3609)

  - An out-of-bounds memory write flaw was found in the Linux kernel's joystick devices subsystem in versions
    before 5.9-rc1, in the way the user calls ioctl JSIOCSBTNMAP. This flaw allows a local user to crash the
    system or possibly escalate their privileges on the system. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system availability. (CVE-2021-3612)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1085224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1094840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1170511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187215");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188274");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-July/009167.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0857a875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3612");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3612");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter x_tables Heap OOB Write Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'kernel-azure-4.12.14-16.65.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-azure-base-4.12.14-16.65.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-azure-devel-4.12.14-16.65.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-devel-azure-4.12.14-16.65.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-source-azure-4.12.14-16.65.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-syms-azure-4.12.14-16.65.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-azure-4.12.14-16.65.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-azure-base-4.12.14-16.65.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-azure-devel-4.12.14-16.65.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-devel-azure-4.12.14-16.65.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-source-azure-4.12.14-16.65.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-syms-azure-4.12.14-16.65.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-azure / kernel-azure-base / kernel-azure-devel / etc');
}
