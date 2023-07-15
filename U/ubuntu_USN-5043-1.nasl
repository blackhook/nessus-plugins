#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5043-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152637);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-32815",
    "CVE-2021-34334",
    "CVE-2021-34335",
    "CVE-2021-37615",
    "CVE-2021-37616",
    "CVE-2021-37618",
    "CVE-2021-37619",
    "CVE-2021-37620",
    "CVE-2021-37621",
    "CVE-2021-37622",
    "CVE-2021-37623"
  );
  script_xref(name:"USN", value:"5043-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.04 : Exiv2 vulnerabilities (USN-5043-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5043-1 advisory.

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. The assertion failure is triggered when Exiv2 is used to modify the metadata of a crafted
    image file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they
    can trick the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when
    modifying the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For
    example, to trigger the bug in the Exiv2 command-line application, you need to add an extra command-line
    argument such as `fi`. ### Patches The bug is fixed in version v0.27.5. ### References Regression test and
    bug fix: #1739 ### For more information Please see our [security
    policy](https://github.com/Exiv2/exiv2/security/policy) for information about Exiv2 security.
    (CVE-2021-32815)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop is triggered when Exiv2 is used to read the metadata of a crafted image
    file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they can
    trick the victim into running Exiv2 on a crafted image file. The bug is fixed in version v0.27.5.
    (CVE-2021-34334)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. A floating point exception (FPE) due to an integer divide by zero was found in Exiv2
    versions v0.27.4 and earlier. The FPE is triggered when Exiv2 is used to print the metadata of a crafted
    image file. An attacker could potentially exploit the vulnerability to cause a denial of service, if they
    can trick the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when
    printing the interpreted (translated) data, which is a less frequently used Exiv2 operation that requires
    an extra command line option (`-p t` or `-P t`). The bug is fixed in version v0.27.5. (CVE-2021-34335)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. A null pointer dereference was found in Exiv2 versions v0.27.4 and earlier. The null
    pointer dereference is triggered when Exiv2 is used to print the metadata of a crafted image file. An
    attacker could potentially exploit the vulnerability to cause a denial of service, if they can trick the
    victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when printing the
    interpreted (translated) data, which is a less frequently used Exiv2 operation that requires an extra
    command line option (`-p t` or `-P t`). The bug is fixed in version v0.27.5. (CVE-2021-37615,
    CVE-2021-37616)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.4 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to print the metadata of a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service, if they can trick the victim into
    running Exiv2 on a crafted image file. Note that this bug is only triggered when printing the image ICC
    profile, which is a less frequently used Exiv2 operation that requires an extra command line option (`-p
    C`). The bug is fixed in version v0.27.5. (CVE-2021-37618)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.4 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service by crashing Exiv2, if they can trick
    the victim into running Exiv2 on a crafted image file. Note that this bug is only triggered when writing
    the metadata, which is a less frequently used Exiv2 operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application, you need to add an extra command-line argument such
    as insert. The bug is fixed in version v0.27.5. (CVE-2021-37619)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in Exiv2 versions v0.27.4 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to read the metadata of a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial of service, if they can trick the victim into
    running Exiv2 on a crafted image file. The bug is fixed in version v0.27.5. (CVE-2021-37620)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop was found in Exiv2 versions v0.27.4 and earlier. The infinite loop is
    triggered when Exiv2 is used to print the metadata of a crafted image file. An attacker could potentially
    exploit the vulnerability to cause a denial of service, if they can trick the victim into running Exiv2 on
    a crafted image file. Note that this bug is only triggered when printing the image ICC profile, which is a
    less frequently used Exiv2 operation that requires an extra command line option (`-p C`). The bug is fixed
    in version v0.27.5. (CVE-2021-37621)

  - Exiv2 is a command-line utility and C++ library for reading, writing, deleting, and modifying the metadata
    of image files. An infinite loop was found in Exiv2 versions v0.27.4 and earlier. The infinite loop is
    triggered when Exiv2 is used to modify the metadata of a crafted image file. An attacker could potentially
    exploit the vulnerability to cause a denial of service, if they can trick the victim into running Exiv2 on
    a crafted image file. Note that this bug is only triggered when deleting the IPTC data, which is a less
    frequently used Exiv2 operation that requires an extra command line option (`-d I rm`). The bug is fixed
    in version v0.27.5. (CVE-2021-37622, CVE-2021-37623)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5043-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37623");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexiv2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexiv2-27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexiv2-dev");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '16.04', 'pkgname': 'exiv2', 'pkgver': '0.25-2.1ubuntu16.04.7+esm4'},
    {'osver': '16.04', 'pkgname': 'libexiv2-14', 'pkgver': '0.25-2.1ubuntu16.04.7+esm4'},
    {'osver': '16.04', 'pkgname': 'libexiv2-dev', 'pkgver': '0.25-2.1ubuntu16.04.7+esm4'},
    {'osver': '18.04', 'pkgname': 'exiv2', 'pkgver': '0.25-3.1ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'libexiv2-14', 'pkgver': '0.25-3.1ubuntu0.18.04.11'},
    {'osver': '18.04', 'pkgname': 'libexiv2-dev', 'pkgver': '0.25-3.1ubuntu0.18.04.11'},
    {'osver': '20.04', 'pkgname': 'exiv2', 'pkgver': '0.27.2-8ubuntu2.6'},
    {'osver': '20.04', 'pkgname': 'libexiv2-27', 'pkgver': '0.27.2-8ubuntu2.6'},
    {'osver': '20.04', 'pkgname': 'libexiv2-dev', 'pkgver': '0.27.2-8ubuntu2.6'},
    {'osver': '21.04', 'pkgname': 'exiv2', 'pkgver': '0.27.3-3ubuntu1.5'},
    {'osver': '21.04', 'pkgname': 'libexiv2-27', 'pkgver': '0.27.3-3ubuntu1.5'},
    {'osver': '21.04', 'pkgname': 'libexiv2-dev', 'pkgver': '0.27.3-3ubuntu1.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'exiv2 / libexiv2-14 / libexiv2-27 / libexiv2-dev');
}
