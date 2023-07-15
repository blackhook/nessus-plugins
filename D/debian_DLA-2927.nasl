#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2927. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158196);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/19");

  script_cve_id("CVE-2020-10108", "CVE-2020-10109", "CVE-2022-21712");

  script_name(english:"Debian DLA-2927-1 : twisted - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2927 advisory.

  - In Twisted Web through 19.10.0, there was an HTTP request splitting vulnerability. When presented with two
    content-length headers, it ignored the first header. When the second content-length value was set to zero,
    the request body was interpreted as a pipelined request. (CVE-2020-10108)

  - In Twisted Web through 19.10.0, there was an HTTP request splitting vulnerability. When presented with a
    content-length and a chunked encoding header, the content-length took precedence and the remainder of the
    request body was interpreted as a pipelined request. (CVE-2020-10109)

  - twisted is an event-driven networking engine written in Python. In affected versions twisted exposes
    cookies and authorization headers when following cross-origin redirects. This issue is present in the
    `twited.web.RedirectAgent` and `twisted.web. BrowserLikeRedirectAgent` functions. Users are advised to
    upgrade. There are no known workarounds. (CVE-2022-21712)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=953950");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/twisted");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2927");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10108");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10109");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21712");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/twisted");
  script_set_attribute(attribute:"solution", value:
"Upgrade the twisted packages.

For Debian 9 stretch, these problems have been fixed in version 16.6.0-2+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10109");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-bin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-conch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-names");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-runner-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-twisted-words");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-twisted-bin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:twisted-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'python-twisted', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-twisted-bin', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-twisted-bin-dbg', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-twisted-conch', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-twisted-core', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-twisted-mail', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-twisted-names', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-twisted-news', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-twisted-runner', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-twisted-runner-dbg', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-twisted-web', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python-twisted-words', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python3-twisted', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python3-twisted-bin', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'python3-twisted-bin-dbg', 'reference': '16.6.0-2+deb9u1'},
    {'release': '9.0', 'prefix': 'twisted-doc', 'reference': '16.6.0-2+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-twisted / python-twisted-bin / python-twisted-bin-dbg / etc');
}
