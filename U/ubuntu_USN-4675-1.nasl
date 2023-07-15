##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4675-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144745);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-29565");
  script_xref(name:"USN", value:"4675-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : OpenStack Horizon vulnerability (USN-4675-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-4675-1 advisory.

  - An issue was discovered in OpenStack Horizon before 15.3.2, 16.x before 16.2.1, 17.x and 18.x before
    18.3.3, 18.4.x, and 18.5.x. There is a lack of validation of the next parameter, which would allow
    someone to supply a malicious URL in Horizon that can cause an automatic redirect to the provided
    malicious URL. (CVE-2020-29565)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4675-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openstack-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openstack-dashboard-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openstack-dashboard-ubuntu-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-django-horizon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-django-openstack-auth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-django-horizon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-django-openstack-auth");
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
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04|18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'openstack-dashboard', 'pkgver': '2:9.1.2-0ubuntu5.2'},
    {'osver': '16.04', 'pkgname': 'openstack-dashboard-ubuntu-theme', 'pkgver': '2:9.1.2-0ubuntu5.2'},
    {'osver': '16.04', 'pkgname': 'python-django-horizon', 'pkgver': '2:9.1.2-0ubuntu5.2'},
    {'osver': '18.04', 'pkgname': 'openstack-dashboard', 'pkgver': '3:13.0.3-0ubuntu2'},
    {'osver': '18.04', 'pkgname': 'openstack-dashboard-ubuntu-theme', 'pkgver': '3:13.0.3-0ubuntu2'},
    {'osver': '18.04', 'pkgname': 'python-django-horizon', 'pkgver': '3:13.0.3-0ubuntu2'},
    {'osver': '18.04', 'pkgname': 'python-django-openstack-auth', 'pkgver': '3:13.0.3-0ubuntu2'},
    {'osver': '18.04', 'pkgname': 'python3-django-openstack-auth', 'pkgver': '3:13.0.3-0ubuntu2'},
    {'osver': '20.04', 'pkgname': 'openstack-dashboard', 'pkgver': '3:18.3.2-0ubuntu0.20.04.4'},
    {'osver': '20.04', 'pkgname': 'openstack-dashboard-common', 'pkgver': '3:18.3.2-0ubuntu0.20.04.4'},
    {'osver': '20.04', 'pkgname': 'openstack-dashboard-ubuntu-theme', 'pkgver': '3:18.3.2-0ubuntu0.20.04.4'},
    {'osver': '20.04', 'pkgname': 'python3-django-horizon', 'pkgver': '3:18.3.2-0ubuntu0.20.04.4'},
    {'osver': '20.04', 'pkgname': 'python3-django-openstack-auth', 'pkgver': '3:18.3.2-0ubuntu0.20.04.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openstack-dashboard / openstack-dashboard-common / etc');
}