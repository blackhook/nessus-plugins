#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5108. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159229);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/25");

  script_cve_id(
    "CVE-2022-0561",
    "CVE-2022-0562",
    "CVE-2022-0865",
    "CVE-2022-0891",
    "CVE-2022-0907",
    "CVE-2022-0908",
    "CVE-2022-0909",
    "CVE-2022-0924",
    "CVE-2022-22844"
  );

  script_name(english:"Debian DSA-5108-1 : tiff - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5108 advisory.

  - Null source pointer passed as an argument to memcpy() function within TIFFFetchStripThing() in
    tif_dirread.c in libtiff versions from 3.9.0 to 4.3.0 could lead to Denial of Service via crafted TIFF
    file. For users that compile libtiff from sources, the fix is available with commit eecb0712.
    (CVE-2022-0561)

  - Null source pointer passed as an argument to memcpy() function within TIFFReadDirectory() in tif_dirread.c
    in libtiff versions from 4.0 to 4.3.0 could lead to Denial of Service via crafted TIFF file. For users
    that compile libtiff from sources, a fix is available with commit 561599c. (CVE-2022-0562)

  - Reachable Assertion in tiffcp in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted
    tiff file. For users that compile libtiff from sources, the fix is available with commit 5e180045.
    (CVE-2022-0865)

  - A heap buffer overflow in ExtractImageSection function in tiffcrop.c in libtiff library Version 4.3.0
    allows attacker to trigger unsafe or out of bounds memory access via crafted TIFF image file which could
    result into application crash, potential information disclosure or any other context-dependent impact
    (CVE-2022-0891)

  - Unchecked Return Value to NULL Pointer Dereference in tiffcrop in libtiff 4.3.0 allows attackers to cause
    a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is
    available with commit f2b656e2. (CVE-2022-0907)

  - Null source pointer passed as an argument to memcpy() function within TIFFFetchNormalTag () in
    tif_dirread.c in libtiff versions up to 4.3.0 could lead to Denial of Service via crafted TIFF file.
    (CVE-2022-0908)

  - Divide By Zero error in tiffcrop in libtiff 4.3.0 allows attackers to cause a denial-of-service via a
    crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f8d0f9aa.
    (CVE-2022-0909)

  - Out-of-bounds Read error in tiffcp in libtiff 4.3.0 allows attackers to cause a denial-of-service via a
    crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 408976c4.
    (CVE-2022-0924)

  - LibTIFF 4.3.0 has an out-of-bounds read in _TIFFmemcpy in tif_unix.c in certain situations involving a
    custom tag and 0x0200 as the second word of the DE field. (CVE-2022-22844)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/tiff");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5108");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0561");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0562");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0865");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0891");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0907");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0908");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0909");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0924");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-22844");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/tiff");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/tiff");
  script_set_attribute(attribute:"solution", value:
"Upgrade the tiff packages.

For the stable distribution (bullseye), these problems have been fixed in version 4.2.0-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0891");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libtiff-dev', 'reference': '4.1.0+git191117-2~deb10u4'},
    {'release': '10.0', 'prefix': 'libtiff-doc', 'reference': '4.1.0+git191117-2~deb10u4'},
    {'release': '10.0', 'prefix': 'libtiff-opengl', 'reference': '4.1.0+git191117-2~deb10u4'},
    {'release': '10.0', 'prefix': 'libtiff-tools', 'reference': '4.1.0+git191117-2~deb10u4'},
    {'release': '10.0', 'prefix': 'libtiff5', 'reference': '4.1.0+git191117-2~deb10u4'},
    {'release': '10.0', 'prefix': 'libtiff5-dev', 'reference': '4.1.0+git191117-2~deb10u4'},
    {'release': '10.0', 'prefix': 'libtiffxx5', 'reference': '4.1.0+git191117-2~deb10u4'},
    {'release': '11.0', 'prefix': 'libtiff-dev', 'reference': '4.2.0-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libtiff-doc', 'reference': '4.2.0-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libtiff-opengl', 'reference': '4.2.0-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libtiff-tools', 'reference': '4.2.0-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libtiff5', 'reference': '4.2.0-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libtiff5-dev', 'reference': '4.2.0-1+deb11u1'},
    {'release': '11.0', 'prefix': 'libtiffxx5', 'reference': '4.2.0-1+deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
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
