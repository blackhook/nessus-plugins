#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5785-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169516);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2019-17185", "CVE-2022-41860", "CVE-2022-41861");
  script_xref(name:"USN", value:"5785-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS : FreeRADIUS vulnerabilities (USN-5785-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5785-1 advisory.

  - In FreeRADIUS 3.0.x before 3.0.20, the EAP-pwd module used a global OpenSSL BN_CTX instance to handle all
    handshakes. This mean multiple threads use the same BN_CTX instance concurrently, resulting in crashes
    when concurrent EAP-pwd handshakes are initiated. This can be abused by an adversary as a Denial-of-
    Service (DoS) attack. (CVE-2019-17185)

  - Crash on unknown option in EAP-SIM (CVE-2022-41860)

  - Crash on invalid abinary data (CVE-2022-41861)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5785-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17185");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-iodbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-memcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freeradius-yubikey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreeradius-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreeradius2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreeradius3");
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
    {'osver': '16.04', 'pkgname': 'freeradius', 'pkgver': '2.2.8+dfsg-0.1ubuntu0.1+esm1'},
    {'osver': '16.04', 'pkgname': 'freeradius-common', 'pkgver': '2.2.8+dfsg-0.1ubuntu0.1+esm1'},
    {'osver': '16.04', 'pkgname': 'freeradius-iodbc', 'pkgver': '2.2.8+dfsg-0.1ubuntu0.1+esm1'},
    {'osver': '16.04', 'pkgname': 'freeradius-krb5', 'pkgver': '2.2.8+dfsg-0.1ubuntu0.1+esm1'},
    {'osver': '16.04', 'pkgname': 'freeradius-ldap', 'pkgver': '2.2.8+dfsg-0.1ubuntu0.1+esm1'},
    {'osver': '16.04', 'pkgname': 'freeradius-mysql', 'pkgver': '2.2.8+dfsg-0.1ubuntu0.1+esm1'},
    {'osver': '16.04', 'pkgname': 'freeradius-postgresql', 'pkgver': '2.2.8+dfsg-0.1ubuntu0.1+esm1'},
    {'osver': '16.04', 'pkgname': 'freeradius-utils', 'pkgver': '2.2.8+dfsg-0.1ubuntu0.1+esm1'},
    {'osver': '16.04', 'pkgname': 'libfreeradius-dev', 'pkgver': '2.2.8+dfsg-0.1ubuntu0.1+esm1'},
    {'osver': '16.04', 'pkgname': 'libfreeradius2', 'pkgver': '2.2.8+dfsg-0.1ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'freeradius', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-common', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-config', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-dhcp', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-iodbc', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-krb5', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-ldap', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-memcached', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-mysql', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-postgresql', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-redis', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-rest', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-utils', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'freeradius-yubikey', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'libfreeradius-dev', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '18.04', 'pkgname': 'libfreeradius3', 'pkgver': '3.0.16+dfsg-1ubuntu3.2'},
    {'osver': '20.04', 'pkgname': 'freeradius', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-common', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-config', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-dhcp', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-iodbc', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-krb5', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-ldap', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-memcached', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-mysql', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-postgresql', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-python3', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-redis', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-rest', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-utils', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'freeradius-yubikey', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libfreeradius-dev', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libfreeradius3', 'pkgver': '3.0.20+dfsg-3ubuntu0.2'},
    {'osver': '22.04', 'pkgname': 'freeradius', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-common', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-config', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-dhcp', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-iodbc', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-krb5', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-ldap', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-memcached', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-mysql', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-postgresql', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-python3', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-redis', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-rest', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-utils', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'freeradius-yubikey', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'libfreeradius-dev', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'},
    {'osver': '22.04', 'pkgname': 'libfreeradius3', 'pkgver': '3.0.26~dfsg~git20220223.1.00ed0241fa-0ubuntu3.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freeradius / freeradius-common / freeradius-config / etc');
}
