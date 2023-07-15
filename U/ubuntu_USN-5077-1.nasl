#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5077-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153367);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-3709", "CVE-2021-3710");
  script_xref(name:"USN", value:"5077-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.04 : Apport vulnerabilities (USN-5077-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5077-1 advisory.

  - An information disclosure via path traversal was discovered in apport/hookutils.py function read_file().
    This issue affects: apport 2.14.1 versions prior to 2.14.1-0ubuntu3.29+esm8; 2.20.1 versions prior to
    2.20.1-0ubuntu2.30+esm2; 2.20.9 versions prior to 2.20.9-0ubuntu7.26; 2.20.11 versions prior to
    2.20.11-0ubuntu27.20; 2.20.11 versions prior to 2.20.11-0ubuntu65.3; (CVE-2021-3710)

  - Function check_attachment_for_errors() in file data/general-hooks/ubuntu.py could be tricked into exposing
    private data via a constructed crash file. This issue affects: apport 2.14.1 versions prior to
    2.14.1-0ubuntu3.29+esm8; 2.20.1 versions prior to 2.20.1-0ubuntu2.30+esm2; 2.20.9 versions prior to
    2.20.9-0ubuntu7.26; 2.20.11 versions prior to 2.20.11-0ubuntu27.20; 2.20.11 versions prior to
    2.20.11-0ubuntu65.3; (CVE-2021-3709)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5077-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3710");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-noui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-retrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport-valgrind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dh-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-problem-report");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-problem-report");
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
if (! preg(pattern:"^(18\.04|20\.04|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'apport', 'pkgver': '2.20.9-0ubuntu7.26'},
    {'osver': '18.04', 'pkgname': 'apport-gtk', 'pkgver': '2.20.9-0ubuntu7.26'},
    {'osver': '18.04', 'pkgname': 'apport-kde', 'pkgver': '2.20.9-0ubuntu7.26'},
    {'osver': '18.04', 'pkgname': 'apport-noui', 'pkgver': '2.20.9-0ubuntu7.26'},
    {'osver': '18.04', 'pkgname': 'apport-retrace', 'pkgver': '2.20.9-0ubuntu7.26'},
    {'osver': '18.04', 'pkgname': 'apport-valgrind', 'pkgver': '2.20.9-0ubuntu7.26'},
    {'osver': '18.04', 'pkgname': 'dh-apport', 'pkgver': '2.20.9-0ubuntu7.26'},
    {'osver': '18.04', 'pkgname': 'python-apport', 'pkgver': '2.20.9-0ubuntu7.26'},
    {'osver': '18.04', 'pkgname': 'python-problem-report', 'pkgver': '2.20.9-0ubuntu7.26'},
    {'osver': '18.04', 'pkgname': 'python3-apport', 'pkgver': '2.20.9-0ubuntu7.26'},
    {'osver': '18.04', 'pkgname': 'python3-problem-report', 'pkgver': '2.20.9-0ubuntu7.26'},
    {'osver': '20.04', 'pkgname': 'apport', 'pkgver': '2.20.11-0ubuntu27.20'},
    {'osver': '20.04', 'pkgname': 'apport-gtk', 'pkgver': '2.20.11-0ubuntu27.20'},
    {'osver': '20.04', 'pkgname': 'apport-kde', 'pkgver': '2.20.11-0ubuntu27.20'},
    {'osver': '20.04', 'pkgname': 'apport-noui', 'pkgver': '2.20.11-0ubuntu27.20'},
    {'osver': '20.04', 'pkgname': 'apport-retrace', 'pkgver': '2.20.11-0ubuntu27.20'},
    {'osver': '20.04', 'pkgname': 'apport-valgrind', 'pkgver': '2.20.11-0ubuntu27.20'},
    {'osver': '20.04', 'pkgname': 'dh-apport', 'pkgver': '2.20.11-0ubuntu27.20'},
    {'osver': '20.04', 'pkgname': 'python3-apport', 'pkgver': '2.20.11-0ubuntu27.20'},
    {'osver': '20.04', 'pkgname': 'python3-problem-report', 'pkgver': '2.20.11-0ubuntu27.20'},
    {'osver': '21.04', 'pkgname': 'apport', 'pkgver': '2.20.11-0ubuntu65.3'},
    {'osver': '21.04', 'pkgname': 'apport-gtk', 'pkgver': '2.20.11-0ubuntu65.3'},
    {'osver': '21.04', 'pkgname': 'apport-kde', 'pkgver': '2.20.11-0ubuntu65.3'},
    {'osver': '21.04', 'pkgname': 'apport-noui', 'pkgver': '2.20.11-0ubuntu65.3'},
    {'osver': '21.04', 'pkgname': 'apport-retrace', 'pkgver': '2.20.11-0ubuntu65.3'},
    {'osver': '21.04', 'pkgname': 'apport-valgrind', 'pkgver': '2.20.11-0ubuntu65.3'},
    {'osver': '21.04', 'pkgname': 'dh-apport', 'pkgver': '2.20.11-0ubuntu65.3'},
    {'osver': '21.04', 'pkgname': 'python3-apport', 'pkgver': '2.20.11-0ubuntu65.3'},
    {'osver': '21.04', 'pkgname': 'python3-problem-report', 'pkgver': '2.20.11-0ubuntu65.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apport / apport-gtk / apport-kde / apport-noui / apport-retrace / etc');
}
