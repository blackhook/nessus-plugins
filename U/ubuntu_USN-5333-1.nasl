#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5333-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159024);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2022-22719",
    "CVE-2022-22720",
    "CVE-2022-22721",
    "CVE-2022-23943"
  );
  script_xref(name:"USN", value:"5333-1");
  script_xref(name:"IAVA", value:"2022-A-0124-S");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : Apache HTTP Server vulnerabilities (USN-5333-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5333-1 advisory.

  - A carefully crafted request body can cause a read to a random memory area which could cause the process to
    crash. This issue affects Apache HTTP Server 2.4.52 and earlier. (CVE-2022-22719)

  - Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered
    discarding the request body, exposing the server to HTTP Request Smuggling (CVE-2022-22720)

  - If LimitXMLRequestBody is set to allow request bodies larger than 350MB (defaults to 1M) on 32 bit systems
    an integer overflow happens which later causes out of bounds writes. This issue affects Apache HTTP Server
    2.4.52 and earlier. (CVE-2022-22721)

  - Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap
    memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 2.4.52 and
    prior versions. (CVE-2022-23943)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5333-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23943");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-ssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-proxy-uwsgi");
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
    {'osver': '18.04', 'pkgname': 'apache2', 'pkgver': '2.4.29-1ubuntu4.22'},
    {'osver': '18.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.29-1ubuntu4.22'},
    {'osver': '18.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.29-1ubuntu4.22'},
    {'osver': '18.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.29-1ubuntu4.22'},
    {'osver': '18.04', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.29-1ubuntu4.22'},
    {'osver': '18.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.29-1ubuntu4.22'},
    {'osver': '18.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.29-1ubuntu4.22'},
    {'osver': '18.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.29-1ubuntu4.22'},
    {'osver': '20.04', 'pkgname': 'apache2', 'pkgver': '2.4.41-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'apache2-bin', 'pkgver': '2.4.41-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'apache2-data', 'pkgver': '2.4.41-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'apache2-dev', 'pkgver': '2.4.41-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.41-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.41-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.41-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'apache2-utils', 'pkgver': '2.4.41-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'libapache2-mod-md', 'pkgver': '2.4.41-4ubuntu3.10'},
    {'osver': '20.04', 'pkgname': 'libapache2-mod-proxy-uwsgi', 'pkgver': '2.4.41-4ubuntu3.10'},
    {'osver': '21.10', 'pkgname': 'apache2', 'pkgver': '2.4.48-3.1ubuntu3.3'},
    {'osver': '21.10', 'pkgname': 'apache2-bin', 'pkgver': '2.4.48-3.1ubuntu3.3'},
    {'osver': '21.10', 'pkgname': 'apache2-data', 'pkgver': '2.4.48-3.1ubuntu3.3'},
    {'osver': '21.10', 'pkgname': 'apache2-dev', 'pkgver': '2.4.48-3.1ubuntu3.3'},
    {'osver': '21.10', 'pkgname': 'apache2-ssl-dev', 'pkgver': '2.4.48-3.1ubuntu3.3'},
    {'osver': '21.10', 'pkgname': 'apache2-suexec-custom', 'pkgver': '2.4.48-3.1ubuntu3.3'},
    {'osver': '21.10', 'pkgname': 'apache2-suexec-pristine', 'pkgver': '2.4.48-3.1ubuntu3.3'},
    {'osver': '21.10', 'pkgname': 'apache2-utils', 'pkgver': '2.4.48-3.1ubuntu3.3'},
    {'osver': '21.10', 'pkgname': 'libapache2-mod-md', 'pkgver': '2.4.48-3.1ubuntu3.3'},
    {'osver': '21.10', 'pkgname': 'libapache2-mod-proxy-uwsgi', 'pkgver': '2.4.48-3.1ubuntu3.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / apache2-ssl-dev / etc');
}
