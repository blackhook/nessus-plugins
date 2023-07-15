#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0480-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158234);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2017-17095",
    "CVE-2019-17546",
    "CVE-2020-19131",
    "CVE-2020-35521",
    "CVE-2020-35522",
    "CVE-2020-35523",
    "CVE-2020-35524",
    "CVE-2022-22844"
  );

  script_name(english:"openSUSE 15 Security Update : tiff (openSUSE-SU-2022:0480-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0480-1 advisory.

  - tools/pal2rgb.c in pal2rgb in LibTIFF 4.0.9 allows remote attackers to cause a denial of service
    (TIFFSetupStrips heap-based buffer overflow and application crash) or possibly have unspecified other
    impact via a crafted TIFF file. (CVE-2017-17095)

  - tif_getimage.c in LibTIFF through 4.0.10, as used in GDAL through 3.0.1 and other products, has an integer
    overflow that potentially causes a heap-based buffer overflow via a crafted RGBA image, related to a
    Negative-size-param condition. (CVE-2019-17546)

  - Buffer Overflow in LibTiff v4.0.10 allows attackers to cause a denial of service via the invertImage()
    function in the component tiffcrop. (CVE-2020-19131)

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

  - LibTIFF 4.3.0 has an out-of-bounds read in _TIFFmemcpy in tif_unix.c in certain situations involving a
    custom tag and 0x0200 as the second word of the DE field. (CVE-2022-22844)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1071031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194539");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7OF4G5SOPBRKT4CZJV5MAQLV5LXXFO62/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaf29637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-17095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-19131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35522");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22844");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35524");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17546");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'libtiff-devel-32bit-4.0.9-45.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff-devel-4.0.9-45.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff5-32bit-4.0.9-45.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libtiff5-4.0.9-45.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tiff-4.0.9-45.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtiff-devel / libtiff-devel-32bit / libtiff5 / libtiff5-32bit / tiff');
}
