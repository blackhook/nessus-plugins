#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3429. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176199);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2021-20176",
    "CVE-2021-20241",
    "CVE-2021-20243",
    "CVE-2021-20244",
    "CVE-2021-20245",
    "CVE-2021-20246",
    "CVE-2021-20309",
    "CVE-2021-20312",
    "CVE-2021-20313",
    "CVE-2021-39212",
    "CVE-2022-28463",
    "CVE-2022-32545",
    "CVE-2022-32546",
    "CVE-2022-32547"
  );
  script_xref(name:"IAVB", value:"2021-B-0017-S");
  script_xref(name:"IAVB", value:"2022-B-0032-S");
  script_xref(name:"IAVB", value:"2022-B-0019-S");

  script_name(english:"Debian DLA-3429-1 : imagemagick - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3429 advisory.

  - A divide-by-zero flaw was found in ImageMagick 6.9.11-57 and 7.0.10-57 in gem.c. This flaw allows an
    attacker who submits a crafted file that is processed by ImageMagick to trigger undefined behavior through
    a division by zero. The highest threat from this vulnerability is to system availability. (CVE-2021-20176)

  - A flaw was found in ImageMagick in coders/jp2.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of math division by zero. The highest threat
    from this vulnerability is to system availability. (CVE-2021-20241)

  - A flaw was found in ImageMagick in MagickCore/resize.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20243)

  - A flaw was found in ImageMagick in MagickCore/visual-effects.c. An attacker who submits a crafted file
    that is processed by ImageMagick could trigger undefined behavior in the form of math division by zero.
    The highest threat from this vulnerability is to system availability. (CVE-2021-20244)

  - A flaw was found in ImageMagick in coders/webp.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of math division by zero. The highest threat
    from this vulnerability is to system availability. (CVE-2021-20245)

  - A flaw was found in ImageMagick in MagickCore/resample.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20246)

  - A flaw was found in ImageMagick in versions before 7.0.11 and before 6.9.12, where a division by zero in
    WaveImage() of MagickCore/visual-effects.c may trigger undefined behavior via a crafted image file
    submitted to an application using ImageMagick. The highest threat from this vulnerability is to system
    availability. (CVE-2021-20309)

  - A flaw was found in ImageMagick in versions 7.0.11, where an integer overflow in WriteTHUMBNAILImage of
    coders/thumbnail.c may trigger undefined behavior via a crafted image file that is submitted by an
    attacker and processed by an application using ImageMagick. The highest threat from this vulnerability is
    to system availability. (CVE-2021-20312)

  - A flaw was found in ImageMagick in versions before 7.0.11. A potential cipher leak when the calculate
    signatures in TransformSignature is possible. The highest threat from this vulnerability is to data
    confidentiality. (CVE-2021-20313)

  - ImageMagick is free software delivered as a ready-to-run binary distribution or as source code that you
    may use, copy, modify, and distribute in both open and proprietary applications. In affected versions and
    in certain cases, Postscript files could be read and written when specifically excluded by a `module`
    policy in `policy.xml`. ex. <policy domain=module rights=none pattern=PS />. The issue has been
    resolved in ImageMagick 7.1.0-7 and in 6.9.12-22. Fortunately, in the wild, few users utilize the `module`
    policy and instead use the `coder` policy that is also our workaround recommendation: <policy
    domain=coder rights=none pattern={PS,EPI,EPS,EPSF,EPSI} />. (CVE-2021-39212)

  - ImageMagick 7.1.0-27 is vulnerable to Buffer Overflow. (CVE-2022-28463)

  - A vulnerability was found in ImageMagick, causing an outside the range of representable values of type
    'unsigned char' at coders/psd.c, when crafted or untrusted input is processed. This leads to a negative
    impact to application availability or other problems related to undefined behavior. (CVE-2022-32545)

  - A vulnerability was found in ImageMagick, causing an outside the range of representable values of type
    'unsigned long' at coders/pcl.c, when crafted or untrusted input is processed. This leads to a negative
    impact to application availability or other problems related to undefined behavior. (CVE-2022-32546)

  - In ImageMagick, there is load of misaligned address for type 'double', which requires 8 byte alignment and
    for type 'float', which requires 4 byte alignment at MagickCore/property.c. Whenever crafted or untrusted
    input is processed by ImageMagick, this causes a negative impact to application availability or other
    problems related to undefined behavior. (CVE-2022-32547)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=996588");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/imagemagick");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3429");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20176");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20241");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20243");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20244");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20245");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20246");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20309");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20312");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20313");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39212");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28463");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32546");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32547");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/imagemagick");
  script_set_attribute(attribute:"solution", value:
"Upgrade the imagemagick packages.

For Debian 10 buster, these problems have been fixed in version 8");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32547");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16hdri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16hdri-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '10.0', 'prefix': 'imagemagick', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-6-common', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-6-doc', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-6.q16', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-6.q16hdri', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-common', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'imagemagick-doc', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libimage-magick-perl', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libimage-magick-q16-perl', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libimage-magick-q16hdri-perl', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-6-headers', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16-8', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16hdri-8', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-6.q16hdri-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagick++-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6-arch-config', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6-headers', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16-6-extra', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16hdri-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16hdri-6-extra', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-6.q16hdri-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickcore-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-6-headers', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16hdri-6', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-6.q16hdri-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'libmagickwand-dev', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'},
    {'release': '10.0', 'prefix': 'perlmagick', 'reference': '8:6.9.10.23+dfsg-2.1+deb10u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'imagemagick / imagemagick-6-common / imagemagick-6-doc / etc');
}
