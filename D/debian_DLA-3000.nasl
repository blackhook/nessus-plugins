#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3000. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161188);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2019-16785",
    "CVE-2019-16786",
    "CVE-2019-16789",
    "CVE-2019-16792",
    "CVE-2022-24761"
  );

  script_name(english:"Debian DLA-3000-1 : waitress - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3000 advisory.

  - Waitress through version 1.3.1 implemented a MAY part of the RFC7230 which states: Although the line
    terminator for the start-line and header fields is the sequence CRLF, a recipient MAY recognize a single
    LF as a line terminator and ignore any preceding CR. Unfortunately if a front-end server does not parse
    header fields with an LF the same way as it does those with a CRLF it can lead to the front-end and the
    back-end server parsing the same HTTP message in two different ways. This can lead to a potential for HTTP
    request smuggling/splitting whereby Waitress may see two requests while the front-end server only sees a
    single HTTP message. This issue is fixed in Waitress 1.4.0. (CVE-2019-16785)

  - Waitress through version 1.3.1 would parse the Transfer-Encoding header and only look for a single string
    value, if that value was not chunked it would fall through and use the Content-Length header instead.
    According to the HTTP standard Transfer-Encoding should be a comma separated list, with the inner-most
    encoding first, followed by any further transfer codings, ending with chunked. Requests sent with:
    Transfer-Encoding: gzip, chunked would incorrectly get ignored, and the request would use a Content-
    Length header instead to determine the body size of the HTTP message. This could allow for Waitress to
    treat a single request as multiple requests in the case of HTTP pipelining. This issue is fixed in
    Waitress 1.4.0. (CVE-2019-16786)

  - In Waitress through version 1.4.0, if a proxy server is used in front of waitress, an invalid request may
    be sent by an attacker that bypasses the front-end and is parsed differently by waitress leading to a
    potential for HTTP request smuggling. Specially crafted requests containing special whitespace characters
    in the Transfer-Encoding header would get parsed by Waitress as being a chunked request, but a front-end
    server would use the Content-Length instead as the Transfer-Encoding header is considered invalid due to
    containing invalid characters. If a front-end server does HTTP pipelining to a backend Waitress server
    this could lead to HTTP request splitting which may lead to potential cache poisoning or unexpected
    information disclosure. This issue is fixed in Waitress 1.4.1 through more strict HTTP field validation.
    (CVE-2019-16789)

  - Waitress through version 1.3.1 allows request smuggling by sending the Content-Length header twice.
    Waitress would header fold a double Content-Length header and due to being unable to cast the now comma
    separated value to an integer would set the Content-Length to 0 internally. If two Content-Length headers
    are sent in a single request, Waitress would treat the request as having no body, thereby treating the
    body of the request as a new request in HTTP pipelining. This issue is fixed in Waitress 1.4.0.
    (CVE-2019-16792)

  - Waitress is a Web Server Gateway Interface server for Python 2 and 3. When using Waitress versions 2.1.0
    and prior behind a proxy that does not properly validate the incoming HTTP request matches the RFC7230
    standard, Waitress and the frontend proxy may disagree on where one request starts and where it ends. This
    would allow requests to be smuggled via the front-end proxy to waitress and later behavior. There are two
    classes of vulnerability that may lead to request smuggling that are addressed by this advisory: The use
    of Python's `int()` to parse strings into integers, leading to `+10` to be parsed as `10`, or `0x01` to be
    parsed as `1`, where as the standard specifies that the string should contain only digits or hex digits;
    and Waitress does not support chunk extensions, however it was discarding them without validating that
    they did not contain illegal characters. This vulnerability has been patched in Waitress 2.1.1. A
    workaround is available. When deploying a proxy in front of waitress, turning on any and all functionality
    to make sure that the request matches the RFC7230 standard. Certain proxy servers may not have this
    functionality though and users are encouraged to upgrade to the latest version of waitress instead.
    (CVE-2022-24761)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1008013");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/waitress");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3000");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16785");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16786");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16789");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16792");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24761");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/waitress");
  script_set_attribute(attribute:"solution", value:
"Upgrade the waitress packages.

For Debian 9 stretch, these problems have been fixed in version 1.0.1-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16789");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-waitress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-waitress-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-waitress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

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
    {'release': '9.0', 'prefix': 'python-waitress', 'reference': '1.0.1-1+deb9u1'},
    {'release': '9.0', 'prefix': 'python-waitress-doc', 'reference': '1.0.1-1+deb9u1'},
    {'release': '9.0', 'prefix': 'python3-waitress', 'reference': '1.0.1-1+deb9u1'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-waitress / python-waitress-doc / python3-waitress');
}
