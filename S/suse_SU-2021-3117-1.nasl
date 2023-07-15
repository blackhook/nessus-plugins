#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3117-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153467);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/17");

  script_cve_id("CVE-2019-5068");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3117-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : Mesa (SUSE-SU-2021:3117-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLES12 host has packages installed that are affected by a vulnerability as referenced in
the SUSE-SU-2021:3117-1 advisory.

  - An exploitable shared memory permissions vulnerability exists in the functionality of X11 Mesa 3D Graphics
    Library 19.1.2. An attacker can access the shared memory without any specific permissions to trigger this
    vulnerability. (CVE-2019-5068)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156015");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-September/009451.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2da6b68d");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-5068");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libEGL1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libEGL1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGL1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGL1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libGLESv2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libglapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:Mesa-libglapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgbm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgbm1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxatracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxatracker2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + sp);
if (os_ver == "SLES12" && (! preg(pattern:"^(2|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'libxatracker-devel-1.0.0-104.9.49', 'sp':'5', 'cpu':'s390x', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libxatracker-devel-1.0.0-104.9.49', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'Mesa-11.2.1-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'Mesa-32bit-11.2.1-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'Mesa-libEGL1-11.2.1-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'Mesa-libEGL1-32bit-11.2.1-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'Mesa-libGL1-11.2.1-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'Mesa-libGL1-32bit-11.2.1-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'Mesa-libGLESv2-2-11.2.1-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'Mesa-libglapi0-11.2.1-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'Mesa-libglapi0-32bit-11.2.1-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libgbm1-11.2.1-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libgbm1-32bit-11.2.1-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libxatracker2-1.0.0-104.9.49', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Mesa / Mesa-32bit / Mesa-libEGL1 / Mesa-libEGL1-32bit / Mesa-libGL1 / etc');
}
