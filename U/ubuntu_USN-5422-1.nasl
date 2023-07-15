##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5422-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161219);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-23308", "CVE-2022-29824");
  script_xref(name:"USN", value:"5422-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS : libxml2 vulnerabilities (USN-5422-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 20.04 LTS / 21.10 / 22.04 LTS host has packages installed that are
affected by multiple vulnerabilities as referenced in the USN-5422-1 advisory.

  - valid.c in libxml2 before 2.9.13 has a use-after-free of ID and IDREF attributes. (CVE-2022-23308)

  - In libxml2 before 2.9.14, several buffer handling functions in buf.c (xmlBuf*) and tree.c (xmlBuffer*)
    don't check for integer overflows. This can result in out-of-bounds memory writes. Exploitation requires a
    victim to open a crafted, multi-gigabyte XML file. Other software using libxml2's buffer functions, for
    example libxslt through 1.1.35, is affected as well. (CVE-2022-29824)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5422-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29824");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23308");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-libxml2");
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
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 21.10 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libxml2', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm2'},
    {'osver': '16.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm2'},
    {'osver': '16.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm2'},
    {'osver': '16.04', 'pkgname': 'python-libxml2', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm2'},
    {'osver': '18.04', 'pkgname': 'libxml2', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.6'},
    {'osver': '18.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.6'},
    {'osver': '18.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.6'},
    {'osver': '18.04', 'pkgname': 'python-libxml2', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.6'},
    {'osver': '18.04', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'python-libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.3'},
    {'osver': '20.04', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.3'},
    {'osver': '21.10', 'pkgname': 'libxml2', 'pkgver': '2.9.12+dfsg-4ubuntu0.2'},
    {'osver': '21.10', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.12+dfsg-4ubuntu0.2'},
    {'osver': '21.10', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.12+dfsg-4ubuntu0.2'},
    {'osver': '21.10', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.12+dfsg-4ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'libxml2', 'pkgver': '2.9.13+dfsg-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.13+dfsg-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.13+dfsg-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.13+dfsg-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxml2 / libxml2-dev / libxml2-utils / python-libxml2 / etc');
}
