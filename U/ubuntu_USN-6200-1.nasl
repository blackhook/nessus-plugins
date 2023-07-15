#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6200-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177934);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2020-29599",
    "CVE-2021-3610",
    "CVE-2021-20224",
    "CVE-2021-20241",
    "CVE-2021-20243",
    "CVE-2021-20244",
    "CVE-2021-20246",
    "CVE-2021-20309",
    "CVE-2021-20312",
    "CVE-2021-20313",
    "CVE-2021-39212",
    "CVE-2022-28463",
    "CVE-2022-32545",
    "CVE-2022-32546",
    "CVE-2022-32547",
    "CVE-2023-1289",
    "CVE-2023-1906",
    "CVE-2023-3195",
    "CVE-2023-3428",
    "CVE-2023-34151"
  );
  script_xref(name:"USN", value:"6200-1");
  script_xref(name:"IAVB", value:"2020-B-0076-S");
  script_xref(name:"IAVB", value:"2021-B-0017-S");
  script_xref(name:"IAVB", value:"2022-B-0019");
  script_xref(name:"IAVB", value:"2022-B-0032-S");
  script_xref(name:"IAVB", value:"2023-B-0020-S");
  script_xref(name:"IAVB", value:"2023-B-0038-S");
  script_xref(name:"IAVB", value:"2023-B-0046");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 ESM / 22.10 / 23.04 : ImageMagick vulnerabilities (USN-6200-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 ESM / 22.10 / 23.04 host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-6200-1 advisory.

  - ImageMagick before 6.9.11-40 and 7.x before 7.0.10-40 mishandles the -authenticate option, which allows
    setting a password for password-protected PDF files. The user-controlled password was not properly
    escaped/sanitized and it was therefore possible to inject additional shell commands via coders/pdf.c.
    (CVE-2020-29599)

  - An integer overflow issue was discovered in ImageMagick's ExportIndexQuantum() function in
    MagickCore/quantum-export.c. Function calls to GetPixelIndex() could result in values outside the range of
    representable for the 'unsigned char'. When ImageMagick processes a crafted pdf file, this could lead to
    an undefined behaviour or a crash. (CVE-2021-20224)

  - A flaw was found in ImageMagick in coders/jp2.c. An attacker who submits a crafted file that is processed
    by ImageMagick could trigger undefined behavior in the form of math division by zero. The highest threat
    from this vulnerability is to system availability. (CVE-2021-20241)

  - A flaw was found in ImageMagick in MagickCore/resize.c. An attacker who submits a crafted file that is
    processed by ImageMagick could trigger undefined behavior in the form of math division by zero. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20243)

  - A flaw was found in ImageMagick in MagickCore/visual-effects.c. An attacker who submits a crafted file
    that is processed by ImageMagick could trigger undefined behavior in the form of math division by zero.
    The highest threat from this vulnerability is to system availability. (CVE-2021-20244)

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

  - A heap-based buffer overflow vulnerability was found in ImageMagick in versions prior to 7.0.11-14 in
    ReadTIFFImage() in coders/tiff.c. This issue is due to an incorrect setting of the pixel array size, which
    can lead to a crash and segmentation fault. (CVE-2021-3610)

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

  - A vulnerability was discovered in ImageMagick where a specially created SVG file loads itself and causes a
    segmentation fault. This flaw allows a remote attacker to pass a specially crafted SVG file that leads to
    a segmentation fault, generating many trash files in /tmp, resulting in a denial of service. When
    ImageMagick crashes, it generates a lot of trash files. These trash files can be large if the SVG file
    contains many render actions. In a denial of service attack, if a remote attacker uploads an SVG file of
    size t, ImageMagick generates files of size 103*t. If an attacker uploads a 100M SVG, the server will
    generate about 10G. (CVE-2023-1289)

  - A heap-based buffer overflow issue was discovered in ImageMagick's ImportMultiSpectralQuantum() function
    in MagickCore/quantum-import.c. An attacker could pass specially crafted file to convert, triggering an
    out-of-bounds read error, allowing an application to crash, resulting in a denial of service.
    (CVE-2023-1906)

  - A stack-based buffer overflow issue was found in ImageMagick's coders/tiff.c. This flaw allows an attacker
    to trick the user into opening a specially crafted malicious tiff file, causing an application to crash,
    resulting in a denial of service. (CVE-2023-3195)

  - A vulnerability was found in ImageMagick. This security flaw ouccers as an undefined behaviors of casting
    double to size_t in svg, mvg and other coders (recurring bugs of CVE-2022-32546). (CVE-2023-34151)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6200-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32547");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16hdri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimage-magick-q16hdri-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-5v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16hdri-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16hdri-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-6-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:perlmagick");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release || '23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagick++-6.q16-5v5', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-2', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-2-extra', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6.q16-2', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '16.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.8.9.9-7ubuntu5.16+esm8'},
    {'osver': '18.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16-7', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16hdri-7', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-3-extra', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-3-extra', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16hdri-3', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '18.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.7.4+dfsg-16ubuntu6.15+esm1'},
    {'osver': '20.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '20.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.10.23+dfsg-2.1ubuntu11.9'},
    {'osver': '22.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.04.3+esm2'},
    {'osver': '22.10', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '22.10', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.11.60+dfsg-1.3ubuntu0.22.10.5'},
    {'osver': '23.04', 'pkgname': 'imagemagick', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'imagemagick-6-common', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'imagemagick-6.q16', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'imagemagick-6.q16hdri', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'imagemagick-common', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libimage-magick-perl', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libimage-magick-q16-perl', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libimage-magick-q16hdri-perl', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagick++-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagick++-6.q16-8', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagick++-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagick++-6.q16hdri-8', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagick++-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagick++-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6-arch-config', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16hdri-6-extra', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickcore-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickcore-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickwand-6-headers', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickwand-6.q16-6', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickwand-6.q16-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickwand-6.q16hdri-6', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickwand-6.q16hdri-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'libmagickwand-dev', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'},
    {'osver': '23.04', 'pkgname': 'perlmagick', 'pkgver': '8:6.9.11.60+dfsg-1.6ubuntu0.23.04.1'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'imagemagick / imagemagick-6-common / imagemagick-6.q16 / etc');
}
