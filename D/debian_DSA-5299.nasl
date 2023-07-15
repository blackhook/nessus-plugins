#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5299. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168623);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/11");

  script_cve_id(
    "CVE-2021-3598",
    "CVE-2021-3605",
    "CVE-2021-3933",
    "CVE-2021-3941",
    "CVE-2021-23215",
    "CVE-2021-26260",
    "CVE-2021-45942"
  );

  script_name(english:"Debian DSA-5299-1 : openexr - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5299 advisory.

  - An integer overflow leading to a heap-buffer overflow was found in the DwaCompressor of OpenEXR in
    versions before 3.0.1. An attacker could use this flaw to crash an application compiled with OpenEXR.
    (CVE-2021-23215)

  - An integer overflow leading to a heap-buffer overflow was found in the DwaCompressor of OpenEXR in
    versions before 3.0.1. An attacker could use this flaw to crash an application compiled with OpenEXR. This
    is a different flaw from CVE-2021-23215. (CVE-2021-26260)

  - There's a flaw in OpenEXR's ImfDeepScanLineInputFile functionality in versions prior to 3.0.5. An attacker
    who is able to submit a crafted file to an application linked with OpenEXR could cause an out-of-bounds
    read. The greatest risk from this flaw is to application availability. (CVE-2021-3598)

  - There's a flaw in OpenEXR's rleUncompress functionality in versions prior to 3.0.5. An attacker who is
    able to submit a crafted file to an application linked with OpenEXR could cause an out-of-bounds read. The
    greatest risk from this flaw is to application availability. (CVE-2021-3605)

  - An integer overflow could occur when OpenEXR processes a crafted file on systems where size_t < 64 bits.
    This could cause an invalid bytesPerLine and maxBytesPerLine value, which could lead to problems with
    application stability or lead to other attack paths. (CVE-2021-3933)

  - In ImfChromaticities.cpp routine RGBtoXYZ(), there are some division operations such as `float Z = (1 -
    chroma.white.x - chroma.white.y) * Y / chroma.white.y;` and `chroma.green.y * (X + Z))) / d;` but the
    divisor is not checked for a 0 value. A specially crafted file could trigger a divide-by-zero condition
    which could affect the availability of programs linked with OpenEXR. (CVE-2021-3941)

  - OpenEXR 3.1.x before 3.1.4 has a heap-based buffer overflow in Imf_3_1::LineCompositeTask::execute (called
    from IlmThread_3_1::NullThreadPoolProvider::addTask and IlmThread_3_1::ThreadPool::addGlobalTask). NOTE:
    db217f2 may be inapplicable. (CVE-2021-45942)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=992703");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openexr");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5299");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23215");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-26260");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3605");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3933");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3941");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45942");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/openexr");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openexr packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.5.4-2+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45942");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3941");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenexr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenexr25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openexr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openexr-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libopenexr-dev', 'reference': '2.5.4-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libopenexr25', 'reference': '2.5.4-2+deb11u1'},
    {'release': '11.0', 'prefix': 'openexr', 'reference': '2.5.4-2+deb11u1'},
    {'release': '11.0', 'prefix': 'openexr-doc', 'reference': '2.5.4-2+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenexr-dev / libopenexr25 / openexr / openexr-doc');
}
