#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:14888-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158178);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2015-8665",
    "CVE-2015-8683",
    "CVE-2020-35521",
    "CVE-2020-35522",
    "CVE-2020-35523",
    "CVE-2020-35524"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:14888-1");

  script_name(english:"SUSE SLES11 Security Update : tiff (SUSE-SU-2022:14888-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:14888-1 advisory.

  - tif_getimage.c in LibTIFF 4.0.6 allows remote attackers to cause a denial of service (out-of-bounds read)
    via the SamplesPerPixel tag in a TIFF image. (CVE-2015-8665)

  - The putcontig8bitCIELab function in tif_getimage.c in LibTIFF 4.0.6 allows remote attackers to cause a
    denial of service (out-of-bounds read) via a packed TIFF image. (CVE-2015-8683)

  - A flaw was found in libtiff. Due to a memory allocation failure in tif_read.c, a crafted TIFF file can
    lead to an abort, resulting in denial of service. (CVE-2020-35521)

  - In LibTIFF, there is a memory malloc failure in tif_pixarlog.c. A crafted TIFF document can lead to an
    abort, resulting in a remote denial of service attack. (CVE-2020-35522)

  - An integer overflow flaw was found in libtiff that exists in the tif_getimage.c file. This flaw allows an
    attacker to inject and execute arbitrary code when a user opens a crafted TIFF file. The highest threat
    from this vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2020-35523)

  - A heap-based buffer overflow flaw was found in libtiff in the handling of TIFF images in libtiff's
    TIFF2PDF tool. A specially crafted TIFF file can lead to arbitrary code execution. The highest threat from
    this vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2020-35524)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182812");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-February/010250.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8528f1f5");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35522");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35524");
  script_set_attribute(attribute:"solution", value:
"Update the affected libtiff3, libtiff3-32bit and / or tiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35524");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libtiff3-3.8.2-141.169.34.1', 'sp':'3', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-pos-release-11.3']},
    {'reference':'tiff-3.8.2-141.169.34.1', 'sp':'3', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-pos-release-11.3']},
    {'reference':'libtiff3-3.8.2-141.169.34.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-11.4']},
    {'reference':'libtiff3-32bit-3.8.2-141.169.34.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-11.4']},
    {'reference':'tiff-3.8.2-141.169.34.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-11.4']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtiff3 / libtiff3-32bit / tiff');
}
