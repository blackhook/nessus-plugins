#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6165-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177323);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/14");

  script_cve_id(
    "CVE-2023-24593",
    "CVE-2023-25180",
    "CVE-2023-29499",
    "CVE-2023-32611",
    "CVE-2023-32636",
    "CVE-2023-32643",
    "CVE-2023-32665"
  );
  script_xref(name:"USN", value:"6165-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : GLib vulnerabilities (USN-6165-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-6165-1 advisory.

  - In GNOME GLib 2.56.1, g_markup_parse_context_end_parse() in gmarkup.c has a NULL pointer dereference.
    (CVE-2018-16428) (CVE-2023-24593, CVE-2023-25180)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6165-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25180");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-tests");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libglib2.0-0', 'pkgver': '2.64.6-1~ubuntu20.04.6'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-bin', 'pkgver': '2.64.6-1~ubuntu20.04.6'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-data', 'pkgver': '2.64.6-1~ubuntu20.04.6'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-dev', 'pkgver': '2.64.6-1~ubuntu20.04.6'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-dev-bin', 'pkgver': '2.64.6-1~ubuntu20.04.6'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-tests', 'pkgver': '2.64.6-1~ubuntu20.04.6'},
    {'osver': '22.04', 'pkgname': 'libglib2.0-0', 'pkgver': '2.72.4-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libglib2.0-bin', 'pkgver': '2.72.4-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libglib2.0-data', 'pkgver': '2.72.4-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libglib2.0-dev', 'pkgver': '2.72.4-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libglib2.0-dev-bin', 'pkgver': '2.72.4-0ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libglib2.0-tests', 'pkgver': '2.72.4-0ubuntu2.2'},
    {'osver': '22.10', 'pkgname': 'libglib2.0-0', 'pkgver': '2.74.3-0ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'libglib2.0-bin', 'pkgver': '2.74.3-0ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'libglib2.0-data', 'pkgver': '2.74.3-0ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'libglib2.0-dev', 'pkgver': '2.74.3-0ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'libglib2.0-dev-bin', 'pkgver': '2.74.3-0ubuntu1.2'},
    {'osver': '22.10', 'pkgname': 'libglib2.0-tests', 'pkgver': '2.74.3-0ubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libglib2.0-0 / libglib2.0-bin / libglib2.0-data / libglib2.0-dev / etc');
}
