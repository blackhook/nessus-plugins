#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5332-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159059);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-25220", "CVE-2022-0396");
  script_xref(name:"USN", value:"5332-1");
  script_xref(name:"IAVA", value:"2022-A-0122-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : Bind vulnerabilities (USN-5332-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5332-1 advisory.

  - BIND 9.16.11 -> 9.16.26, 9.17.0 -> 9.18.0 and versions 9.16.11-S1 -> 9.16.26-S1 of the BIND Supported
    Preview Edition. Specifically crafted TCP streams can cause connections to BIND to remain in CLOSE_WAIT
    status for an indefinite period of time, even after the client has terminated the connection.
    (CVE-2022-0396)

  - BIND 9.11.0 -> 9.11.36 9.12.0 -> 9.16.26 9.17.0 -> 9.18.0 BIND Supported Preview Editions: 9.11.4-S1 ->
    9.11.36-S1 9.16.8-S1 -> 9.16.26-S1 Versions of BIND 9 earlier than those shown - back to 9.1.0, including
    Supported Preview Editions - are also believed to be affected but have not been tested as they are EOL.
    The cache could become poisoned with incorrect records leading to queries being made to the wrong servers,
    which might also result in false information being returned to clients. (CVE-2021-25220)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5332-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25220");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind-export-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns-export1100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns1100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs-export160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc-export169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc169");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc-export160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg-export160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres160");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(18\.04|20\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'bind9', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libbind-dev', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libbind-export-dev', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libbind9-160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libdns-export1100', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libdns1100', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libirs-export160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libirs160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libisc-export169', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libisc169', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libisccc-export160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libisccc160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libisccfg-export160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'libisccfg160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '18.04', 'pkgname': 'liblwres160', 'pkgver': '1:9.11.3+dfsg-1ubuntu1.17'},
    {'osver': '20.04', 'pkgname': 'bind9', 'pkgver': '1:9.16.1-0ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'bind9-dnsutils', 'pkgver': '1:9.16.1-0ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.16.1-0ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'bind9-libs', 'pkgver': '1:9.16.1-0ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'bind9-utils', 'pkgver': '1:9.16.1-0ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.16.1-0ubuntu2.10'},
    {'osver': '20.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.16.1-0ubuntu2.10'},
    {'osver': '21.10', 'pkgname': 'bind9', 'pkgver': '1:9.16.15-1ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'bind9-dev', 'pkgver': '1:9.16.15-1ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'bind9-dnsutils', 'pkgver': '1:9.16.15-1ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'bind9-host', 'pkgver': '1:9.16.15-1ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'bind9-libs', 'pkgver': '1:9.16.15-1ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'bind9-utils', 'pkgver': '1:9.16.15-1ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'bind9utils', 'pkgver': '1:9.16.15-1ubuntu1.2'},
    {'osver': '21.10', 'pkgname': 'dnsutils', 'pkgver': '1:9.16.15-1ubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind9 / bind9-dev / bind9-dnsutils / bind9-host / bind9-libs / etc');
}
