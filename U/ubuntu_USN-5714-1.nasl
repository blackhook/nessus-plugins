#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5714-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167166);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-2519",
    "CVE-2022-2520",
    "CVE-2022-2521",
    "CVE-2022-2867",
    "CVE-2022-2868",
    "CVE-2022-2869",
    "CVE-2022-2953",
    "CVE-2022-3570",
    "CVE-2022-3597",
    "CVE-2022-3598",
    "CVE-2022-3599",
    "CVE-2022-3626",
    "CVE-2022-3627",
    "CVE-2022-34526"
  );
  script_xref(name:"USN", value:"5714-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : LibTIFF vulnerabilities (USN-5714-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5714-1 advisory.

  - There is a double free or corruption in rotateImage() at tiffcrop.c:8839 found in libtiff 4.4.0rc1
    (CVE-2022-2519)

  - A flaw was found in libtiff 4.4.0rc1. There is a sysmalloc assertion fail in rotateImage() at
    tiffcrop.c:8621 that can cause program crash when reading a crafted input. (CVE-2022-2520)

  - It was found in libtiff 4.4.0rc1 that there is an invalid pointer free operation in TIFFClose() at
    tif_close.c:131 called by tiffcrop.c:2522 that can cause a program crash and denial of service while
    processing crafted input. (CVE-2022-2521)

  - libtiff's tiffcrop utility has a uint32_t underflow that can lead to out of bounds read and write. An
    attacker who supplies a crafted file to tiffcrop (likely via tricking a user to run tiffcrop on it with
    certain parameters) could cause a crash or in some cases, further exploitation. (CVE-2022-2867)

  - libtiff's tiffcrop utility has a improper input validation flaw that can lead to out of bounds read and
    ultimately cause a crash if an attacker is able to supply a crafted file to tiffcrop. (CVE-2022-2868)

  - libtiff's tiffcrop tool has a uint32_t underflow which leads to out of bounds read and write in the
    extractContigSamples8bits routine. An attacker who supplies a crafted file to tiffcrop could trigger this
    flaw, most likely by tricking a user into opening the crafted file with tiffcrop. Triggering this flaw
    could cause a crash or potentially further exploitation. (CVE-2022-2869)

  - LibTIFF 4.4.0 has an out-of-bounds read in extractImageSection in tools/tiffcrop.c:6905, allowing
    attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from
    sources, the fix is available with commit 48d6ece8. (CVE-2022-2953)

  - Multiple heap buffer overflows in tiffcrop.c utility in libtiff library Version 4.4.0 allows attacker to
    trigger unsafe or out of bounds memory access via crafted TIFF image file which could result into
    application crash, potential information disclosure or any other context-dependent impact (CVE-2022-3570)

  - LibTIFF 4.4.0 has an out-of-bounds write in extractContigSamplesShifted24bits in tools/tiffcrop.c:3604,
    allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff
    from sources, the fix is available with commit cfbb883b. (CVE-2022-3598)

  - LibTIFF 4.4.0 has an out-of-bounds read in writeSingleSection in tools/tiffcrop.c:7345, allowing attackers
    to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix
    is available with commit e8131125. (CVE-2022-3599)

  - LibTIFF 4.4.0 has an out-of-bounds write in _TIFFmemset in libtiff/tif_unix.c:340 when called from
    processCropSelections, tools/tiffcrop.c:7619, allowing attackers to cause a denial-of-service via a
    crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 236b7191.
    (CVE-2022-3626)

  - LibTIFF 4.4.0 has an out-of-bounds write in _TIFFmemcpy in libtiff/tif_unix.c:346 when called from
    extractImageSection, tools/tiffcrop.c:6860, allowing attackers to cause a denial-of-service via a crafted
    tiff file. For users that compile libtiff from sources, the fix is available with commit 236b7191.
    (CVE-2022-3627)

  - A stack overflow was discovered in the _TIFFVGetField function of Tiffsplit v4.4.0. This vulnerability
    allows attackers to cause a Denial of Service (DoS) via a crafted TIFF file. (CVE-2022-34526)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5714-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3627");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff5-alt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiffxx5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libtiff-opengl', 'pkgver': '4.0.6-1ubuntu0.8+esm7'},
    {'osver': '16.04', 'pkgname': 'libtiff-tools', 'pkgver': '4.0.6-1ubuntu0.8+esm7'},
    {'osver': '16.04', 'pkgname': 'libtiff5', 'pkgver': '4.0.6-1ubuntu0.8+esm7'},
    {'osver': '16.04', 'pkgname': 'libtiff5-dev', 'pkgver': '4.0.6-1ubuntu0.8+esm7'},
    {'osver': '16.04', 'pkgname': 'libtiffxx5', 'pkgver': '4.0.6-1ubuntu0.8+esm7'},
    {'osver': '18.04', 'pkgname': 'libtiff-dev', 'pkgver': '4.0.9-5ubuntu0.8'},
    {'osver': '18.04', 'pkgname': 'libtiff-opengl', 'pkgver': '4.0.9-5ubuntu0.8'},
    {'osver': '18.04', 'pkgname': 'libtiff-tools', 'pkgver': '4.0.9-5ubuntu0.8'},
    {'osver': '18.04', 'pkgname': 'libtiff5', 'pkgver': '4.0.9-5ubuntu0.8'},
    {'osver': '18.04', 'pkgname': 'libtiff5-dev', 'pkgver': '4.0.9-5ubuntu0.8'},
    {'osver': '18.04', 'pkgname': 'libtiffxx5', 'pkgver': '4.0.9-5ubuntu0.8'},
    {'osver': '20.04', 'pkgname': 'libtiff-dev', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.6'},
    {'osver': '20.04', 'pkgname': 'libtiff-opengl', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.6'},
    {'osver': '20.04', 'pkgname': 'libtiff-tools', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.6'},
    {'osver': '20.04', 'pkgname': 'libtiff5', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.6'},
    {'osver': '20.04', 'pkgname': 'libtiff5-dev', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.6'},
    {'osver': '20.04', 'pkgname': 'libtiffxx5', 'pkgver': '4.1.0+git191117-2ubuntu0.20.04.6'},
    {'osver': '22.04', 'pkgname': 'libtiff-dev', 'pkgver': '4.3.0-6ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libtiff-opengl', 'pkgver': '4.3.0-6ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libtiff-tools', 'pkgver': '4.3.0-6ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libtiff5', 'pkgver': '4.3.0-6ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libtiff5-dev', 'pkgver': '4.3.0-6ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libtiffxx5', 'pkgver': '4.3.0-6ubuntu0.2'},
    {'osver': '22.10', 'pkgname': 'libtiff-dev', 'pkgver': '4.4.0-4ubuntu3.1'},
    {'osver': '22.10', 'pkgname': 'libtiff-opengl', 'pkgver': '4.4.0-4ubuntu3.1'},
    {'osver': '22.10', 'pkgname': 'libtiff-tools', 'pkgver': '4.4.0-4ubuntu3.1'},
    {'osver': '22.10', 'pkgname': 'libtiff5', 'pkgver': '4.4.0-4ubuntu3.1'},
    {'osver': '22.10', 'pkgname': 'libtiff5-dev', 'pkgver': '4.4.0-4ubuntu3.1'},
    {'osver': '22.10', 'pkgname': 'libtiffxx5', 'pkgver': '4.4.0-4ubuntu3.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtiff-dev / libtiff-opengl / libtiff-tools / libtiff5 / etc');
}
