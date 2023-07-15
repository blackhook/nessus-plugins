#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6073-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175600);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/29");

  script_cve_id("CVE-2023-2088");
  script_xref(name:"USN", value:"6073-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 / 23.04 : Cinder vulnerability (USN-6073-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 22.10 / 23.04 host has packages installed that are affected by a vulnerability
as referenced in the USN-6073-1 advisory.

  - A flaw was found in OpenStack due to an inconsistency between Cinder and Nova. This issue can be triggered
    intentionally or by accident. A remote, authenticated attacker could exploit this vulnerability by
    detaching one of their volumes from Cinder. The highest impact is to confidentiality. (CVE-2023-2088)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6073-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cinder-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cinder-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cinder-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cinder-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cinder-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-cinder");
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
if (! preg(pattern:"^(20\.04|22\.04|22\.10|23\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'cinder-api', 'pkgver': '2:16.4.2-0ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'cinder-backup', 'pkgver': '2:16.4.2-0ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'cinder-common', 'pkgver': '2:16.4.2-0ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'cinder-scheduler', 'pkgver': '2:16.4.2-0ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'cinder-volume', 'pkgver': '2:16.4.2-0ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'python3-cinder', 'pkgver': '2:16.4.2-0ubuntu2.3'},
    {'osver': '22.04', 'pkgname': 'cinder-api', 'pkgver': '2:20.1.0-0ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'cinder-backup', 'pkgver': '2:20.1.0-0ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'cinder-common', 'pkgver': '2:20.1.0-0ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'cinder-scheduler', 'pkgver': '2:20.1.0-0ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'cinder-volume', 'pkgver': '2:20.1.0-0ubuntu2.1'},
    {'osver': '22.04', 'pkgname': 'python3-cinder', 'pkgver': '2:20.1.0-0ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'cinder-api', 'pkgver': '2:21.1.0-0ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'cinder-backup', 'pkgver': '2:21.1.0-0ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'cinder-common', 'pkgver': '2:21.1.0-0ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'cinder-scheduler', 'pkgver': '2:21.1.0-0ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'cinder-volume', 'pkgver': '2:21.1.0-0ubuntu2.1'},
    {'osver': '22.10', 'pkgname': 'python3-cinder', 'pkgver': '2:21.1.0-0ubuntu2.1'},
    {'osver': '23.04', 'pkgname': 'cinder-api', 'pkgver': '2:22.0.0-0ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'cinder-backup', 'pkgver': '2:22.0.0-0ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'cinder-common', 'pkgver': '2:22.0.0-0ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'cinder-scheduler', 'pkgver': '2:22.0.0-0ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'cinder-volume', 'pkgver': '2:22.0.0-0ubuntu1.1'},
    {'osver': '23.04', 'pkgname': 'python3-cinder', 'pkgver': '2:22.0.0-0ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cinder-api / cinder-backup / cinder-common / cinder-scheduler / etc');
}
