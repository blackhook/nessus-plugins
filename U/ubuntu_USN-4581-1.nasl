##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4581-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141459);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-26116");
  script_xref(name:"USN", value:"4581-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Python vulnerability (USN-4581-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-4581-1 advisory.

  - http.client in Python 3.x before 3.5.10, 3.6.x before 3.6.12, 3.7.x before 3.7.9, and 3.8.x before 3.8.5
    allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR
    and LF control characters in the first argument of HTTPConnection.request. (CVE-2020-26116)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4581-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26116");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.4-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.5-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.6-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.5-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.6-venv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.13'},
    {'osver': '16.04', 'pkgname': 'idle-python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.12'},
    {'osver': '16.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.13'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.12-1ubuntu0~16.04.13'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.12-1ubuntu0~16.04.13'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.12-1ubuntu0~16.04.13'},
    {'osver': '16.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.12-1ubuntu0~16.04.13'},
    {'osver': '16.04', 'pkgname': 'libpython3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.12'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.12'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.12'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-stdlib', 'pkgver': '3.5.2-2ubuntu0~16.04.12'},
    {'osver': '16.04', 'pkgname': 'libpython3.5-testsuite', 'pkgver': '3.5.2-2ubuntu0~16.04.12'},
    {'osver': '16.04', 'pkgname': 'python2.7', 'pkgver': '2.7.12-1ubuntu0~16.04.13'},
    {'osver': '16.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.12-1ubuntu0~16.04.13'},
    {'osver': '16.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.12-1ubuntu0~16.04.13'},
    {'osver': '16.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.12-1ubuntu0~16.04.13'},
    {'osver': '16.04', 'pkgname': 'python3.5', 'pkgver': '3.5.2-2ubuntu0~16.04.12'},
    {'osver': '16.04', 'pkgname': 'python3.5-dev', 'pkgver': '3.5.2-2ubuntu0~16.04.12'},
    {'osver': '16.04', 'pkgname': 'python3.5-examples', 'pkgver': '3.5.2-2ubuntu0~16.04.12'},
    {'osver': '16.04', 'pkgname': 'python3.5-minimal', 'pkgver': '3.5.2-2ubuntu0~16.04.12'},
    {'osver': '16.04', 'pkgname': 'python3.5-venv', 'pkgver': '3.5.2-2ubuntu0~16.04.12'},
    {'osver': '18.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'idle-python3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.17-1~18.04ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.17-1~18.04ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.17-1~18.04ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.17-1~18.04ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'libpython3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libpython3.6-dev', 'pkgver': '3.6.9-1~18.04ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libpython3.6-minimal', 'pkgver': '3.6.9-1~18.04ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libpython3.6-stdlib', 'pkgver': '3.6.9-1~18.04ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libpython3.6-testsuite', 'pkgver': '3.6.9-1~18.04ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'python2.7', 'pkgver': '2.7.17-1~18.04ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.17-1~18.04ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.17-1~18.04ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.17-1~18.04ubuntu1.2'},
    {'osver': '18.04', 'pkgname': 'python3.6', 'pkgver': '3.6.9-1~18.04ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'python3.6-dev', 'pkgver': '3.6.9-1~18.04ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'python3.6-examples', 'pkgver': '3.6.9-1~18.04ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'python3.6-minimal', 'pkgver': '3.6.9-1~18.04ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'python3.6-venv', 'pkgver': '3.6.9-1~18.04ubuntu1.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python2.7 / idle-python3.5 / idle-python3.6 / libpython2.7 / etc');
}