#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3236. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168916);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/19");

  script_cve_id(
    "CVE-2020-16587",
    "CVE-2020-16588",
    "CVE-2020-16589",
    "CVE-2021-3474",
    "CVE-2021-3475",
    "CVE-2021-3476",
    "CVE-2021-3477",
    "CVE-2021-3478",
    "CVE-2021-3479",
    "CVE-2021-3598",
    "CVE-2021-3605",
    "CVE-2021-3933",
    "CVE-2021-3941",
    "CVE-2021-20296",
    "CVE-2021-20298",
    "CVE-2021-20299",
    "CVE-2021-20300",
    "CVE-2021-20302",
    "CVE-2021-20303",
    "CVE-2021-23215",
    "CVE-2021-26260",
    "CVE-2021-45942"
  );

  script_name(english:"Debian DLA-3236-1 : openexr - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3236 advisory.

  - A heap-based buffer overflow vulnerability exists in Academy Software Foundation OpenEXR 2.3.0 in
    chunkOffsetReconstruction in ImfMultiPartInputFile.cpp that can cause a denial of service via a crafted
    EXR file. (CVE-2020-16587)

  - A Null Pointer Deference issue exists in Academy Software Foundation OpenEXR 2.3.0 in generatePreview in
    makePreview.cpp that can cause a denial of service via a crafted EXR file. (CVE-2020-16588)

  - A head-based buffer overflow exists in Academy Software Foundation OpenEXR 2.3.0 in writeTileData in
    ImfTiledOutputFile.cpp that can cause a denial of service via a crafted EXR file. (CVE-2020-16589)

  - A flaw was found in OpenEXR in versions before 3.0.0-beta. A crafted input file supplied by an attacker,
    that is processed by the Dwa decompression functionality of OpenEXR's IlmImf library, could cause a NULL
    pointer dereference. The highest threat from this vulnerability is to system availability.
    (CVE-2021-20296)

  - A flaw was found in OpenEXR's B44Compressor. This flaw allows an attacker who can submit a crafted file to
    be processed by OpenEXR, to exhaust all memory accessible to the application. The highest threat from this
    vulnerability is to system availability. (CVE-2021-20298)

  - A flaw was found in OpenEXR's Multipart input file functionality. A crafted multi-part input file with no
    actual parts can trigger a NULL pointer dereference. The highest threat from this vulnerability is to
    system availability. (CVE-2021-20299)

  - A flaw was found in OpenEXR's hufUncompress functionality in OpenEXR/IlmImf/ImfHuf.cpp. This flaw allows
    an attacker who can submit a crafted file that is processed by OpenEXR, to trigger an integer overflow.
    The highest threat from this vulnerability is to system availability. (CVE-2021-20300)

  - A flaw was found in OpenEXR's TiledInputFile functionality. This flaw allows an attacker who can submit a
    crafted single-part non-image to be processed by OpenEXR, to trigger a floating-point exception error. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20302)

  - A flaw found in function dataWindowForTile() of IlmImf/ImfTiledMisc.cpp. An attacker who is able to submit
    a crafted file to be processed by OpenEXR could trigger an integer overflow, leading to an out-of-bounds
    write on the heap. The greatest impact of this flaw is to application availability, with some potential
    impact to data integrity as well. (CVE-2021-20303)

  - An integer overflow leading to a heap-buffer overflow was found in the DwaCompressor of OpenEXR in
    versions before 3.0.1. An attacker could use this flaw to crash an application compiled with OpenEXR.
    (CVE-2021-23215)

  - An integer overflow leading to a heap-buffer overflow was found in the DwaCompressor of OpenEXR in
    versions before 3.0.1. An attacker could use this flaw to crash an application compiled with OpenEXR. This
    is a different flaw from CVE-2021-23215. (CVE-2021-26260)

  - There's a flaw in OpenEXR in versions before 3.0.0-beta. A crafted input file that is processed by OpenEXR
    could cause a shift overflow in the FastHufDecoder, potentially leading to problems with application
    availability. (CVE-2021-3474)

  - There is a flaw in OpenEXR in versions before 3.0.0-beta. An attacker who can submit a crafted file to be
    processed by OpenEXR could cause an integer overflow, potentially leading to problems with application
    availability. (CVE-2021-3475)

  - A flaw was found in OpenEXR's B44 uncompression functionality in versions before 3.0.0-beta. An attacker
    who is able to submit a crafted file to OpenEXR could trigger shift overflows, potentially affecting
    application availability. (CVE-2021-3476)

  - There's a flaw in OpenEXR's deep tile sample size calculations in versions before 3.0.0-beta. An attacker
    who is able to submit a crafted file to be processed by OpenEXR could trigger an integer overflow,
    subsequently leading to an out-of-bounds read. The greatest risk of this flaw is to application
    availability. (CVE-2021-3477)

  - There's a flaw in OpenEXR's scanline input file functionality in versions before 3.0.0-beta. An attacker
    able to submit a crafted file to be processed by OpenEXR could consume excessive system memory. The
    greatest impact of this flaw is to system availability. (CVE-2021-3478)

  - There's a flaw in OpenEXR's Scanline API functionality in versions before 3.0.0-beta. An attacker who is
    able to submit a crafted file to be processed by OpenEXR could trigger excessive consumption of memory,
    resulting in an impact to system availability. (CVE-2021-3479)

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
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=986796");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openexr");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3236");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-16587");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-16588");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-16589");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20296");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20298");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20299");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20300");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20302");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20303");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23215");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-26260");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3474");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3475");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3476");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3477");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3478");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3479");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3598");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3605");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3933");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3941");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45942");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/openexr");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openexr packages.

For Debian 10 buster, these problems have been fixed in version 2.2.1-4.1+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenexr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenexr23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openexr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openexr-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libopenexr-dev', 'reference': '2.2.1-4.1+deb10u2'},
    {'release': '10.0', 'prefix': 'libopenexr23', 'reference': '2.2.1-4.1+deb10u2'},
    {'release': '10.0', 'prefix': 'openexr', 'reference': '2.2.1-4.1+deb10u2'},
    {'release': '10.0', 'prefix': 'openexr-doc', 'reference': '2.2.1-4.1+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenexr-dev / libopenexr23 / openexr / openexr-doc');
}
