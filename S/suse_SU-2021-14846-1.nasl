#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14846-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155801);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-3941",
    "CVE-2021-20298",
    "CVE-2021-20300",
    "CVE-2021-20303",
    "CVE-2021-20304"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14846-1");

  script_name(english:"SUSE SLES11 Security Update : OpenEXR (SUSE-SU-2021:14846-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14846-1 advisory.

  - A flaw found in function dataWindowForTile() of IlmImf/ImfTiledMisc.cpp. An attacker who is able to submit
    a crafted file to be processed by OpenEXR could trigger an integer overflow, leading to an out-of-bounds
    write on the heap. The greatest impact of this flaw is to application availability, with some potential
    impact to data integrity as well. (CVE-2021-20303)

  - In ImfChromaticities.cpp routine RGBtoXYZ(), there are some division operations such as `float Z = (1 -
    chroma.white.x - chroma.white.y) * Y / chroma.white.y;` and `chroma.green.y * (X + Z))) / d;` but the
    divisor is not checked for a 0 value. A specially crafted file could trigger a divide-by-zero condition
    which could affect the availability of programs linked with OpenEXR. (CVE-2021-3941)

  - A flaw was found in OpenEXR's B44Compressor. This flaw allows an attacker who can submit a crafted file to
    be processed by OpenEXR, to exhaust all memory accessible to the application. The highest threat from this
    vulnerability is to system availability. (CVE-2021-20298)

  - A flaw was found in OpenEXR's hufUncompress functionality in OpenEXR/IlmImf/ImfHuf.cpp. This flaw allows
    an attacker who can submit a crafted file that is processed by OpenEXR, to trigger an integer overflow.
    The highest threat from this vulnerability is to system availability. (CVE-2021-20300)

  - A flaw was found in OpenEXR's hufDecode functionality. This flaw allows an attacker who can pass a crafted
    file to be processed by OpenEXR, to trigger an undefined right shift error. The highest threat from this
    vulnerability is to system availability. (CVE-2021-20304)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192556");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-December/009786.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90a56434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20298");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20300");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20303");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20304");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3941");
  script_set_attribute(attribute:"solution", value:
"Update the affected OpenEXR and / or OpenEXR-32bit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:OpenEXR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:OpenEXR-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'OpenEXR-1.6.1-83.17.30.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'OpenEXR-32bit-1.6.1-83.17.30.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'OpenEXR-32bit-1.6.1-83.17.30.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'OpenEXR / OpenEXR-32bit');
}
