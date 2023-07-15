##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5543-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163680);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-24805",
    "CVE-2022-24806",
    "CVE-2022-24807",
    "CVE-2022-24808",
    "CVE-2022-24809",
    "CVE-2022-24810"
  );
  script_xref(name:"USN", value:"5543-1");
  script_xref(name:"IAVA", value:"2022-A-0305");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : Net-SNMP vulnerabilities (USN-5543-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5543-1 advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5543-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24810");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnetsnmptrapd40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp35");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsnmp40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-netsnmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:snmpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:snmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tkmib");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libsnmp-base', 'pkgver': '5.7.3+dfsg-1.8ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libsnmp-dev', 'pkgver': '5.7.3+dfsg-1.8ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libsnmp-perl', 'pkgver': '5.7.3+dfsg-1.8ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'libsnmp30', 'pkgver': '5.7.3+dfsg-1.8ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'python-netsnmp', 'pkgver': '5.7.3+dfsg-1.8ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'snmp', 'pkgver': '5.7.3+dfsg-1.8ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'snmpd', 'pkgver': '5.7.3+dfsg-1.8ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'snmptrapd', 'pkgver': '5.7.3+dfsg-1.8ubuntu3.7'},
    {'osver': '18.04', 'pkgname': 'tkmib', 'pkgver': '5.7.3+dfsg-1.8ubuntu3.7'},
    {'osver': '20.04', 'pkgname': 'libsnmp-base', 'pkgver': '5.8+dfsg-2ubuntu2.4'},
    {'osver': '20.04', 'pkgname': 'libsnmp-dev', 'pkgver': '5.8+dfsg-2ubuntu2.4'},
    {'osver': '20.04', 'pkgname': 'libsnmp-perl', 'pkgver': '5.8+dfsg-2ubuntu2.4'},
    {'osver': '20.04', 'pkgname': 'libsnmp35', 'pkgver': '5.8+dfsg-2ubuntu2.4'},
    {'osver': '20.04', 'pkgname': 'snmp', 'pkgver': '5.8+dfsg-2ubuntu2.4'},
    {'osver': '20.04', 'pkgname': 'snmpd', 'pkgver': '5.8+dfsg-2ubuntu2.4'},
    {'osver': '20.04', 'pkgname': 'snmptrapd', 'pkgver': '5.8+dfsg-2ubuntu2.4'},
    {'osver': '20.04', 'pkgname': 'tkmib', 'pkgver': '5.8+dfsg-2ubuntu2.4'},
    {'osver': '22.04', 'pkgname': 'libnetsnmptrapd40', 'pkgver': '5.9.1+dfsg-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libsnmp-base', 'pkgver': '5.9.1+dfsg-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libsnmp-dev', 'pkgver': '5.9.1+dfsg-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libsnmp-perl', 'pkgver': '5.9.1+dfsg-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'libsnmp40', 'pkgver': '5.9.1+dfsg-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'snmp', 'pkgver': '5.9.1+dfsg-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'snmpd', 'pkgver': '5.9.1+dfsg-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'snmptrapd', 'pkgver': '5.9.1+dfsg-1ubuntu2.2'},
    {'osver': '22.04', 'pkgname': 'tkmib', 'pkgver': '5.9.1+dfsg-1ubuntu2.2'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnetsnmptrapd40 / libsnmp-base / libsnmp-dev / libsnmp-perl / etc');
}
