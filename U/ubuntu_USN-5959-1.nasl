#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5959-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172631);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id("CVE-2021-36222", "CVE-2021-37750");
  script_xref(name:"USN", value:"5959-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Kerberos vulnerabilities (USN-5959-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5959-1 advisory.

  - ec_verify in kdc/kdc_preauth_ec.c in the Key Distribution Center (KDC) in MIT Kerberos 5 (aka krb5) before
    1.18.4 and 1.19.x before 1.19.2 allows remote attackers to cause a NULL pointer dereference and daemon
    crash. This occurs because a return value is not properly managed in a certain situation. (CVE-2021-36222)

  - The Key Distribution Center (KDC) in MIT Kerberos 5 (aka krb5) before 1.18.5 and 1.19.x before 1.19.3 has
    a NULL pointer dereference in kdc/do_tgs_req.c via a FAST inner body that lacks a server field.
    (CVE-2021-37750)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5959-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-gss-samples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-k5tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kpropd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssapi-krb5-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgssrpc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libk5crypto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5clnt-mit11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm5srv-mit11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkdb5-9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrad-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrad0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5support0");
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
if (! preg(pattern:"^(18\.04|20\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'krb5-k5tls', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'krb5-kpropd', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'krb5-locales', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'krb5-otp', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'krb5-user', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libgssrpc4', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libkadm5clnt-mit11', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libkadm5srv-mit11', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libkdb5-9', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libkrad0', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '18.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.16-2ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'krb5-admin-server', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'krb5-gss-samples', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'krb5-k5tls', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'krb5-kdc', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'krb5-kdc-ldap', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'krb5-kpropd', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'krb5-locales', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'krb5-multidev', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'krb5-otp', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'krb5-pkinit', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'krb5-user', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'libgssapi-krb5-2', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'libgssrpc4', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'libk5crypto3', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'libkadm5clnt-mit11', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'libkadm5srv-mit11', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'libkdb5-9', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'libkrad-dev', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'libkrad0', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'libkrb5-3', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'libkrb5-dev', 'pkgver': '1.17-6ubuntu4.3'},
    {'osver': '20.04', 'pkgname': 'libkrb5support0', 'pkgver': '1.17-6ubuntu4.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'krb5-admin-server / krb5-gss-samples / krb5-k5tls / krb5-kdc / etc');
}
