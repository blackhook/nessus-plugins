#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:2615-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152246);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/06");

  script_cve_id(
    "CVE-2018-13139",
    "CVE-2018-19432",
    "CVE-2018-19758",
    "CVE-2021-3246"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:2615-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libsndfile (SUSE-SU-2021:2615-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLES12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2021:2615-1 advisory.

  - A stack-based buffer overflow in psf_memset in common.c in libsndfile 1.0.28 allows remote attackers to
    cause a denial of service (application crash) or possibly have unspecified other impact via a crafted
    audio file. The vulnerability can be triggered by the executable sndfile-deinterleave. (CVE-2018-13139)

  - An issue was discovered in libsndfile 1.0.28. There is a NULL pointer dereference in the function
    sf_write_int in sndfile.c, which will lead to a denial of service. (CVE-2018-19432)

  - There is a heap-based buffer over-read at wav.c in wav_write_header in libsndfile 1.0.28 that will cause a
    denial of service. (CVE-2018-19758)

  - A heap buffer overflow vulnerability in msadpcm_decode_block of libsndfile 1.0.30 allows attackers to
    execute arbitrary code via a crafted WAV file. (CVE-2021-3246)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1100167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1116993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1117954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188540");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-August/009252.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a13e731");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-13139");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19432");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3246");
  script_set_attribute(attribute:"solution", value:
"Update the affected libsndfile-devel, libsndfile1 and / or libsndfile1-32bit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3246");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsndfile-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsndfile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsndfile1-32bit");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'libsndfile1-1.0.25-36.23.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'libsndfile1-32bit-1.0.25-36.23.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'libsndfile1-1.0.25-36.23.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'libsndfile1-32bit-1.0.25-36.23.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'libsndfile1-1.0.25-36.23.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libsndfile1-32bit-1.0.25-36.23.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libsndfile-devel-1.0.25-36.23.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libsndfile-devel-1.0.25-36.23.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'libsndfile1-1.0.25-36.23.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libsndfile1-32bit-1.0.25-36.23.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libsndfile1-1.0.25-36.23.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libsndfile1-1.0.25-36.23.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libsndfile1-32bit-1.0.25-36.23.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libsndfile1-32bit-1.0.25-36.23.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libsndfile1-1.0.25-36.23.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'libsndfile1-32bit-1.0.25-36.23.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'libsndfile1-1.0.25-36.23.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libsndfile1-32bit-1.0.25-36.23.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'}
];

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
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = '\n' +
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsndfile-devel / libsndfile1 / libsndfile1-32bit');
}
