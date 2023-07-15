#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3477. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177875);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/01");

  script_cve_id(
    "CVE-2015-20107",
    "CVE-2020-10735",
    "CVE-2021-3426",
    "CVE-2021-3733",
    "CVE-2021-3737",
    "CVE-2021-4189",
    "CVE-2022-45061"
  );

  script_name(english:"Debian DLA-3477-1 : python3.7 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3477 advisory.

  - In Python (aka CPython) up to 3.10.8, the mailcap module does not add escape characters into commands
    discovered in the system mailcap file. This may allow attackers to inject shell commands into applications
    that call mailcap.findmatch with untrusted input (if they lack validation of user-provided filenames or
    arguments). The fix is also back-ported to 3.7, 3.8, 3.9 (CVE-2015-20107)

  - A flaw was found in python. In algorithms with quadratic time complexity using non-binary bases, when
    using int(text), a system could take 50ms to parse an int string with 100,000 digits and 5s for
    1,000,000 digits (float, decimal, int.from_bytes(), and int() for binary bases 2, 4, 8, 16, and 32 are not
    affected). The highest threat from this vulnerability is to system availability. (CVE-2020-10735)

  - There's a flaw in Python 3's pydoc. A local or adjacent attacker who discovers or is able to convince
    another local or adjacent user to start a pydoc server could access the server and use it to disclose
    sensitive information belonging to the other user that they would not normally be able to access. The
    highest risk of this flaw is to data confidentiality. This flaw affects Python versions before 3.8.9,
    Python versions before 3.9.3 and Python versions before 3.10.0a7. (CVE-2021-3426)

  - There's a flaw in urllib's AbstractBasicAuthHandler class. An attacker who controls a malicious HTTP
    server that an HTTP client (such as web browser) connects to, could trigger a Regular Expression Denial of
    Service (ReDOS) during an authentication request with a specially crafted payload that is sent by the
    server to the client. The greatest threat that this flaw poses is to application availability.
    (CVE-2021-3733)

  - A flaw was found in python. An improperly handled HTTP response in the HTTP client code of python may
    allow a remote attacker, who controls the HTTP server, to make the client script enter an infinite loop,
    consuming CPU time. The highest threat from this vulnerability is to system availability. (CVE-2021-3737)

  - A flaw was found in Python, specifically in the FTP (File Transfer Protocol) client library in PASV
    (passive) mode. The issue is how the FTP client trusts the host from the PASV response by default. This
    flaw allows an attacker to set up a malicious FTP server that can trick FTP clients into connecting back
    to a given IP address and port. This vulnerability could lead to FTP client scanning ports, which
    otherwise would not have been possible. (CVE-2021-4189)

  - An issue was discovered in Python before 3.11.1. An unnecessary quadratic algorithm exists in one path
    when processing some inputs to the IDNA (RFC 3490) decoder, such that a crafted, unreasonably long name
    being presented to the decoder could lead to a CPU denial of service. Hostnames are often supplied by
    remote servers that could be controlled by a malicious actor; in such a scenario, they could trigger
    excessive CPU consumption on the client attempting to make use of an attacker-supplied supposed hostname.
    For example, the attack payload could be placed in the Location header of an HTTP response with status
    code 302. A fix is planned in 3.11.1, 3.10.9, 3.9.16, 3.8.16, and 3.7.16. (CVE-2022-45061)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/python3.7");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3477");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2015-20107");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10735");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3426");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3733");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3737");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4189");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45061");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/python3.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python3.7 packages.

For Debian 10 buster, these problems have been fixed in version 3.7.3-2+deb10u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-20107");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.7-venv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'idle-python3.7', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7-dbg', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7-dev', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7-minimal', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7-stdlib', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'libpython3.7-testsuite', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-dbg', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-dev', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-doc', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-examples', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-minimal', 'reference': '3.7.3-2+deb10u5'},
    {'release': '10.0', 'prefix': 'python3.7-venv', 'reference': '3.7.3-2+deb10u5'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python3.7 / libpython3.7 / libpython3.7-dbg / libpython3.7-dev / etc');
}
