#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5301-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158259);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-24407");
  script_xref(name:"USN", value:"5301-1");

  script_name(english:"Ubuntu 20.04 LTS : Cyrus SASL vulnerability (USN-5301-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-5301-1 advisory.

  - In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL
    INSERT or UPDATE statement. (CVE-2022-24407)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5301-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules-gssapi-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules-gssapi-mit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sasl2-bin");
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
if (! ('18.04' >< os_release || '20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libsasl2-2', 'pkgver': '2.1.27~101-g0780600+dfsg-3ubuntu2.4'},
    {'osver': '18.04', 'pkgname': 'libsasl2-dev', 'pkgver': '2.1.27~101-g0780600+dfsg-3ubuntu2.4'},
    {'osver': '18.04', 'pkgname': 'libsasl2-modules', 'pkgver': '2.1.27~101-g0780600+dfsg-3ubuntu2.4'},
    {'osver': '18.04', 'pkgname': 'libsasl2-modules-db', 'pkgver': '2.1.27~101-g0780600+dfsg-3ubuntu2.4'},
    {'osver': '18.04', 'pkgname': 'libsasl2-modules-gssapi-heimdal', 'pkgver': '2.1.27~101-g0780600+dfsg-3ubuntu2.4'},
    {'osver': '18.04', 'pkgname': 'libsasl2-modules-gssapi-mit', 'pkgver': '2.1.27~101-g0780600+dfsg-3ubuntu2.4'},
    {'osver': '18.04', 'pkgname': 'libsasl2-modules-ldap', 'pkgver': '2.1.27~101-g0780600+dfsg-3ubuntu2.4'},
    {'osver': '18.04', 'pkgname': 'libsasl2-modules-otp', 'pkgver': '2.1.27~101-g0780600+dfsg-3ubuntu2.4'},
    {'osver': '18.04', 'pkgname': 'libsasl2-modules-sql', 'pkgver': '2.1.27~101-g0780600+dfsg-3ubuntu2.4'},
    {'osver': '18.04', 'pkgname': 'sasl2-bin', 'pkgver': '2.1.27~101-g0780600+dfsg-3ubuntu2.4'},
    {'osver': '20.04', 'pkgname': 'libsasl2-2', 'pkgver': '2.1.27+dfsg-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libsasl2-dev', 'pkgver': '2.1.27+dfsg-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libsasl2-modules', 'pkgver': '2.1.27+dfsg-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libsasl2-modules-db', 'pkgver': '2.1.27+dfsg-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libsasl2-modules-gssapi-heimdal', 'pkgver': '2.1.27+dfsg-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libsasl2-modules-gssapi-mit', 'pkgver': '2.1.27+dfsg-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libsasl2-modules-ldap', 'pkgver': '2.1.27+dfsg-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libsasl2-modules-otp', 'pkgver': '2.1.27+dfsg-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libsasl2-modules-sql', 'pkgver': '2.1.27+dfsg-2ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'sasl2-bin', 'pkgver': '2.1.27+dfsg-2ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsasl2-2', 'pkgver': '2.1.27+dfsg-2.1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsasl2-dev', 'pkgver': '2.1.27+dfsg-2.1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsasl2-modules', 'pkgver': '2.1.27+dfsg-2.1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsasl2-modules-db', 'pkgver': '2.1.27+dfsg-2.1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsasl2-modules-gssapi-heimdal', 'pkgver': '2.1.27+dfsg-2.1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsasl2-modules-gssapi-mit', 'pkgver': '2.1.27+dfsg-2.1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsasl2-modules-ldap', 'pkgver': '2.1.27+dfsg-2.1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsasl2-modules-otp', 'pkgver': '2.1.27+dfsg-2.1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libsasl2-modules-sql', 'pkgver': '2.1.27+dfsg-2.1ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'sasl2-bin', 'pkgver': '2.1.27+dfsg-2.1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsasl2-2 / libsasl2-dev / libsasl2-modules / libsasl2-modules-db / etc');
}
