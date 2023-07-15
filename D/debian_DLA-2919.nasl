#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2919. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158032);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-3177", "CVE-2021-4189");
  script_xref(name:"IAVA", value:"2021-A-0052-S");

  script_name(english:"Debian DLA-2919-1 : python2.7 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2919 advisory.

  - Python 3.x through 3.9.1 has a buffer overflow in PyCArg_repr in _ctypes/callproc.c, which may lead to
    remote code execution in certain Python applications that accept floating-point numbers as untrusted
    input, as demonstrated by a 1e300 argument to c_double.from_param. This occurs because sprintf is used
    unsafely. (CVE-2021-3177)

  - A flaw was found in Python, specifically in the FTP (File Transfer Protocol) client library in PASV
    (passive) mode. The issue is how the FTP client trusts the host from the PASV response by default. This
    flaw allows an attacker to set up a malicious FTP server that can trick FTP clients into connecting back
    to a given IP address and port. This vulnerability could lead to FTP client scanning ports, which
    otherwise would not have been possible. (CVE-2021-4189)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/python2.7");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2919");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3177");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4189");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/python2.7");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python2.7 packages.

For Debian 9 stretch, these problems have been fixed in version 2.7.13-2+deb9u6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3177");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'idle-python2.7', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'libpython2.7', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'libpython2.7-dbg', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'libpython2.7-dev', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'libpython2.7-minimal', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'libpython2.7-stdlib', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'libpython2.7-testsuite', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'python2.7', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'python2.7-dbg', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'python2.7-dev', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'python2.7-doc', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'python2.7-examples', 'reference': '2.7.13-2+deb9u6'},
    {'release': '9.0', 'prefix': 'python2.7-minimal', 'reference': '2.7.13-2+deb9u6'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'idle-python2.7 / libpython2.7 / libpython2.7-dbg / libpython2.7-dev / etc');
}
