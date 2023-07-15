#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3278. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(170240);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/21");

  script_cve_id(
    "CVE-2022-1354",
    "CVE-2022-1355",
    "CVE-2022-2056",
    "CVE-2022-2057",
    "CVE-2022-2058",
    "CVE-2022-2867",
    "CVE-2022-2868",
    "CVE-2022-2869",
    "CVE-2022-3570",
    "CVE-2022-3597",
    "CVE-2022-3598",
    "CVE-2022-3599",
    "CVE-2022-3626",
    "CVE-2022-3627",
    "CVE-2022-3970",
    "CVE-2022-34526"
  );

  script_name(english:"Debian DLA-3278-1 : tiff - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3278 advisory.

  - A heap buffer overflow flaw was found in Libtiffs' tiffinfo.c in TIFFReadRawDataStriped() function. This
    flaw allows an attacker to pass a crafted TIFF file to the tiffinfo tool, triggering a heap buffer
    overflow issue and causing a crash that leads to a denial of service. (CVE-2022-1354)

  - A stack buffer overflow flaw was found in Libtiffs' tiffcp.c in main() function. This flaw allows an
    attacker to pass a crafted TIFF file to the tiffcp tool, triggering a stack buffer overflow issue,
    possibly corrupting the memory, and causing a crash that leads to a denial of service. (CVE-2022-1355)

  - Divide By Zero error in tiffcrop in libtiff 4.4.0 allows attackers to cause a denial-of-service via a
    crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f3a5e010.
    (CVE-2022-2056, CVE-2022-2057, CVE-2022-2058)

  - libtiff's tiffcrop utility has a uint32_t underflow that can lead to out of bounds read and write. An
    attacker who supplies a crafted file to tiffcrop (likely via tricking a user to run tiffcrop on it with
    certain parameters) could cause a crash or in some cases, further exploitation. (CVE-2022-2867)

  - libtiff's tiffcrop utility has a improper input validation flaw that can lead to out of bounds read and
    ultimately cause a crash if an attacker is able to supply a crafted file to tiffcrop. (CVE-2022-2868)

  - libtiff's tiffcrop tool has a uint32_t underflow which leads to out of bounds read and write in the
    extractContigSamples8bits routine. An attacker who supplies a crafted file to tiffcrop could trigger this
    flaw, most likely by tricking a user into opening the crafted file with tiffcrop. Triggering this flaw
    could cause a crash or potentially further exploitation. (CVE-2022-2869)

  - A stack overflow was discovered in the _TIFFVGetField function of Tiffsplit v4.4.0. This vulnerability
    allows attackers to cause a Denial of Service (DoS) via a crafted TIFF file parsed by the tiffsplit or
    tiffcrop utilities. (CVE-2022-34526)

  - Multiple heap buffer overflows in tiffcrop.c utility in libtiff library Version 4.4.0 allows attacker to
    trigger unsafe or out of bounds memory access via crafted TIFF image file which could result into
    application crash, potential information disclosure or any other context-dependent impact (CVE-2022-3570)

  - LibTIFF 4.4.0 has an out-of-bounds write in _TIFFmemcpy in libtiff/tif_unix.c:346 when called from
    extractImageSection, tools/tiffcrop.c:6826, allowing attackers to cause a denial-of-service via a crafted
    tiff file. For users that compile libtiff from sources, the fix is available with commit 236b7191.
    (CVE-2022-3597)

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

  - A vulnerability was found in LibTIFF. It has been classified as critical. This affects the function
    TIFFReadRGBATileExt of the file libtiff/tif_getimage.c. The manipulation leads to integer overflow. It is
    possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.
    The name of the patch is 227500897dfb07fb7d27f7aa570050e62617e3be. It is recommended to apply a patch to
    fix this issue. The identifier VDB-213549 was assigned to this vulnerability. (CVE-2022-3970)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1011160");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/tiff");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3278");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1354");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1355");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2056");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2057");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2058");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2867");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2868");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2869");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34526");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3570");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3597");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3599");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3626");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3627");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3970");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/tiff");
  script_set_attribute(attribute:"solution", value:
"Upgrade the tiff packages.

For Debian 10 buster, these problems have been fixed in version 4.1.0+git191117-2~deb10u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2058");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3970");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libtiff-dev', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiff-doc', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiff-opengl', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiff-tools', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiff5', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiff5-dev', 'reference': '4.1.0+git191117-2~deb10u5'},
    {'release': '10.0', 'prefix': 'libtiffxx5', 'reference': '4.1.0+git191117-2~deb10u5'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtiff-dev / libtiff-doc / libtiff-opengl / libtiff-tools / libtiff5 / etc');
}
