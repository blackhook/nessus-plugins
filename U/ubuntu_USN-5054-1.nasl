#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5054-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152913);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-11984");
  script_xref(name:"USN", value:"5054-1");
  script_xref(name:"IAVA", value:"2021-A-0032");
  script_xref(name:"IAVA", value:"2020-A-0376-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Ubuntu 18.04 LTS : uWSGI vulnerability (USN-5054-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-5054-1 advisory.

  - Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and possible RCE (CVE-2020-11984)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5054-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11984");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-proxy-uwsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-ruwsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-uwsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-uwsgidecorators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-uwsgidecorators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-app-integration-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-emperor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-infrastructure-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-alarm-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-alarm-xmpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-asyncio-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-asyncio-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-curl-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-emperor-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-fiber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-gccgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-gevent-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-graylog2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-greenlet-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-jvm-openjdk-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-jwsgi-openjdk-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-lua5.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-lua5.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-psgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-rack-ruby2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-rbthreads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-ring-openjdk-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-router-access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-servlet-openjdk-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-tornado-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugin-xslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-plugins-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uwsgi-src");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'libapache2-mod-proxy-uwsgi', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'libapache2-mod-ruwsgi', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'libapache2-mod-uwsgi', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'python-uwsgidecorators', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'python3-uwsgidecorators', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-app-integration-plugins', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-core', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-dev', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-emperor', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-extra', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-infrastructure-plugins', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-alarm-curl', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-alarm-xmpp', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-asyncio-python', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-asyncio-python3', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-curl-cron', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-emperor-pg', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-fiber', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-gccgo', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-geoip', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-gevent-python', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-glusterfs', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-graylog2', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-greenlet-python', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-jvm-openjdk-8', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-jwsgi-openjdk-8', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-ldap', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-lua5.1', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-lua5.2', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-mono', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-psgi', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-python', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-python3', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-rack-ruby2.5', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-rados', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-rbthreads', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-ring-openjdk-8', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-router-access', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-servlet-openjdk-8', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-sqlite3', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-tornado-python', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugin-xslt', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-plugins-all', 'pkgver': '2.0.15-10.2ubuntu2.2'},
    {'osver': '18.04', 'pkgname': 'uwsgi-src', 'pkgver': '2.0.15-10.2ubuntu2.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-proxy-uwsgi / libapache2-mod-ruwsgi / etc');
}
