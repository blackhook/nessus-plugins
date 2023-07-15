##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4754-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148008);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2019-9674",
    "CVE-2019-17514",
    "CVE-2019-20907",
    "CVE-2020-8492",
    "CVE-2020-26116",
    "CVE-2020-27619",
    "CVE-2021-3177"
  );
  script_xref(name:"USN", value:"4754-3");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Python vulnerabilities (USN-4754-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-4754-3 advisory.

  - Lib/zipfile.py in Python through 3.7.2 allows remote attackers to cause a denial of service (resource
    consumption) via a ZIP bomb. (CVE-2019-9674)

  - library/glob.html in the Python 2 and 3 documentation before 2016 has potentially misleading information
    about whether sorting occurs, as demonstrated by irreproducible cancer-research results. NOTE: the effects
    of this documentation cross application domains, and thus it is likely that security-relevant code
    elsewhere is affected. This issue is not a Python implementation bug, and there are no reports that NMR
    researchers were specifically relying on library/glob.html. In other words, because the older
    documentation stated finds all the pathnames matching a specified pattern according to the rules used by
    the Unix shell, one might have incorrectly inferred that the sorting that occurs in a Unix shell also
    occurred for glob.glob. There is a workaround in newer versions of Willoughby nmr-data_compilation-p2.py
    and nmr-data_compilation-p3.py, which call sort() directly. (CVE-2019-17514)

  - In Lib/tarfile.py in Python through 3.8.3, an attacker is able to craft a TAR archive leading to an
    infinite loop when opened by tarfile.open, because _proc_pax lacks header validation. (CVE-2019-20907)

  - Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6 through 3.6.10, 3.7 through 3.7.6, and 3.8 through 3.8.1
    allows an HTTP server to conduct Regular Expression Denial of Service (ReDoS) attacks against a client
    because of urllib.request.AbstractBasicAuthHandler catastrophic backtracking. (CVE-2020-8492)

  - http.client in Python 3.x before 3.5.10, 3.6.x before 3.6.12, 3.7.x before 3.7.9, and 3.8.x before 3.8.5
    allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR
    and LF control characters in the first argument of HTTPConnection.request. (CVE-2020-26116)

  - In Python 3 through 3.9.0, the Lib/test/multibytecodec_support.py CJK codec tests call eval() on content
    retrieved via HTTP. (CVE-2020-27619)

  - Python 3.x through 3.9.1 has a buffer overflow in PyCArg_repr in _ctypes/callproc.c, which may lead to
    remote code execution in certain Python applications that accept floating-point numbers as untrusted
    input, as demonstrated by a 1e300 argument to c_double.from_param. This occurs because sprintf is used
    unsafely. (CVE-2021-3177)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4754-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython2.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpython3.8-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.7-venv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.8-venv");
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
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'idle-python3.7', 'pkgver': '3.7.5-2~18.04.4'},
    {'osver': '18.04', 'pkgname': 'idle-python3.8', 'pkgver': '3.8.0-3~18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpython3.7', 'pkgver': '3.7.5-2~18.04.4'},
    {'osver': '18.04', 'pkgname': 'libpython3.7-dev', 'pkgver': '3.7.5-2~18.04.4'},
    {'osver': '18.04', 'pkgname': 'libpython3.7-minimal', 'pkgver': '3.7.5-2~18.04.4'},
    {'osver': '18.04', 'pkgname': 'libpython3.7-stdlib', 'pkgver': '3.7.5-2~18.04.4'},
    {'osver': '18.04', 'pkgname': 'libpython3.7-testsuite', 'pkgver': '3.7.5-2~18.04.4'},
    {'osver': '18.04', 'pkgname': 'libpython3.8', 'pkgver': '3.8.0-3~18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpython3.8-dev', 'pkgver': '3.8.0-3~18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpython3.8-minimal', 'pkgver': '3.8.0-3~18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpython3.8-stdlib', 'pkgver': '3.8.0-3~18.04.1'},
    {'osver': '18.04', 'pkgname': 'libpython3.8-testsuite', 'pkgver': '3.8.0-3~18.04.1'},
    {'osver': '18.04', 'pkgname': 'python3.7', 'pkgver': '3.7.5-2~18.04.4'},
    {'osver': '18.04', 'pkgname': 'python3.7-dev', 'pkgver': '3.7.5-2~18.04.4'},
    {'osver': '18.04', 'pkgname': 'python3.7-examples', 'pkgver': '3.7.5-2~18.04.4'},
    {'osver': '18.04', 'pkgname': 'python3.7-minimal', 'pkgver': '3.7.5-2~18.04.4'},
    {'osver': '18.04', 'pkgname': 'python3.7-venv', 'pkgver': '3.7.5-2~18.04.4'},
    {'osver': '18.04', 'pkgname': 'python3.8', 'pkgver': '3.8.0-3~18.04.1'},
    {'osver': '18.04', 'pkgname': 'python3.8-dev', 'pkgver': '3.8.0-3~18.04.1'},
    {'osver': '18.04', 'pkgname': 'python3.8-examples', 'pkgver': '3.8.0-3~18.04.1'},
    {'osver': '18.04', 'pkgname': 'python3.8-minimal', 'pkgver': '3.8.0-3~18.04.1'},
    {'osver': '18.04', 'pkgname': 'python3.8-venv', 'pkgver': '3.8.0-3~18.04.1'},
    {'osver': '20.04', 'pkgname': 'idle-python2.7', 'pkgver': '2.7.18-1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpython2.7', 'pkgver': '2.7.18-1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpython2.7-dev', 'pkgver': '2.7.18-1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpython2.7-minimal', 'pkgver': '2.7.18-1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpython2.7-stdlib', 'pkgver': '2.7.18-1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'libpython2.7-testsuite', 'pkgver': '2.7.18-1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'python2.7', 'pkgver': '2.7.18-1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'python2.7-dev', 'pkgver': '2.7.18-1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'python2.7-examples', 'pkgver': '2.7.18-1~20.04.1'},
    {'osver': '20.04', 'pkgname': 'python2.7-minimal', 'pkgver': '2.7.18-1~20.04.1'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python2.7 / idle-python3.7 / idle-python3.8 / libpython2.7 / etc');
}