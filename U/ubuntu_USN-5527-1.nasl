##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5527-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163287);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2017-9781",
    "CVE-2017-14955",
    "CVE-2021-36563",
    "CVE-2021-40906",
    "CVE-2022-24565"
  );
  script_xref(name:"USN", value:"5527-1");

  script_name(english:"Ubuntu 18.04 LTS : Checkmk vulnerabilities (USN-5527-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5527-1 advisory.

  - A cross site scripting (XSS) vulnerability exists in Check_MK versions 1.4.0x prior to 1.4.0p6, allowing
    an unauthenticated remote attacker to inject arbitrary HTML or JavaScript via the _username parameter when
    attempting authentication to webapi.py, which is returned unencoded with content type text/html.
    (CVE-2017-9781)

  - Check_MK before 1.2.8p26 mishandles certain errors within the failed-login save feature because of a race
    condition, which allows remote attackers to obtain sensitive user information by reading a GUI crash
    report. (CVE-2017-14955)

  - The CheckMK management web console (versions 1.5.0 to 2.0.0) does not sanitise user input in various
    parameters of the WATO module. This allows an attacker to open a backdoor on the device with HTML content
    and interpreted by the browser (such as JavaScript or other client-side scripts), the XSS payload will be
    triggered when the user accesses some specific sections of the application. In the same sense a very
    dangerous potential way would be when an attacker who has the monitor role (not administrator) manages to
    get a stored XSS to steal the secretAutomation (for the use of the API in administrator mode) and thus be
    able to create another administrator user who has high privileges on the CheckMK monitoring web console.
    Another way is that persistent XSS allows an attacker to modify the displayed content or change the
    victim's information. Successful exploitation requires access to the web management interface, either with
    valid credentials or with a hijacked session. (CVE-2021-36563)

  - CheckMK Raw Edition software (versions 1.5.0 to 1.6.0) does not sanitise the input of a web service
    parameter that is in an unauthenticated zone. This Reflected XSS allows an attacker to open a backdoor on
    the device with HTML content and interpreted by the browser (such as JavaScript or other client-side
    scripts) or to steal the session cookies of a user who has previously authenticated via a man in the
    middle. Successful exploitation requires access to the web service resource without authentication.
    (CVE-2021-40906)

  - Checkmk <=2.0.0p19 Fixed in 2.0.0p20 and Checkmk <=1.6.0p27 Fixed in 1.6.0p28 are affected by a Cross Site
    Scripting (XSS) vulnerability. The Alias of a site was not properly escaped when shown as condition for
    notifications. (CVE-2022-24565)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5527-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40906");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:check-mk-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:check-mk-agent-logwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:check-mk-config-icinga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:check-mk-livestatus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:check-mk-multisite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:check-mk-server");
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
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'check-mk-agent', 'pkgver': '1.2.8p16-1ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'check-mk-agent-logwatch', 'pkgver': '1.2.8p16-1ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'check-mk-config-icinga', 'pkgver': '1.2.8p16-1ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'check-mk-livestatus', 'pkgver': '1.2.8p16-1ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'check-mk-multisite', 'pkgver': '1.2.8p16-1ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'check-mk-server', 'pkgver': '1.2.8p16-1ubuntu0.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'check-mk-agent / check-mk-agent-logwatch / check-mk-config-icinga / etc');
}
