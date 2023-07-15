#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6176-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177426);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id("CVE-2022-24859");
  script_xref(name:"USN", value:"6176-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS : PyPDF2 vulnerability (USN-6176-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS host has packages installed that are affected by a
vulnerability as referenced in the USN-6176-1 advisory.

  - PyPDF2 is an open source python PDF library capable of splitting, merging, cropping, and transforming the
    pages of PDF files. In versions prior to 1.27.5 an attacker who uses this vulnerability can craft a PDF
    which leads to an infinite loop if the PyPDF2 if the code attempts to get the content stream. The reason
    is that the last while-loop in `ContentStream._readInlineImage` only terminates when it finds the `EI`
    token, but never actually checks if the stream has already ended. This issue has been resolved in version
    `1.27.5`. Users unable to upgrade should validate and PDFs prior to iterating over their content stream.
    (CVE-2022-24859)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6176-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-pypdf2 and / or python3-pypdf2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24859");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-pypdf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-pypdf2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'python-pypdf2', 'pkgver': '1.25.1-1ubuntu0.1~esm1'},
    {'osver': '16.04', 'pkgname': 'python3-pypdf2', 'pkgver': '1.25.1-1ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'python-pypdf2', 'pkgver': '1.26.0-2ubuntu0.1~esm1'},
    {'osver': '18.04', 'pkgname': 'python3-pypdf2', 'pkgver': '1.26.0-2ubuntu0.1~esm1'},
    {'osver': '20.04', 'pkgname': 'python-pypdf2', 'pkgver': '1.26.0-3ubuntu1.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-pypdf2', 'pkgver': '1.26.0-3ubuntu1.20.04.1'},
    {'osver': '22.04', 'pkgname': 'python3-pypdf2', 'pkgver': '1.26.0-4ubuntu0.22.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-pypdf2 / python3-pypdf2');
}
