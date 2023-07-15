#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2628-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148749);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/21");

  script_cve_id("CVE-2019-16935", "CVE-2021-23336");

  script_name(english:"Debian DLA-2628-1 : python2.7 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Two security issues have been discovered in python2.7 :

CVE-2019-16935

The documentation XML-RPC server in Python 2.7 has XSS via the
server_title field. This occurs in Lib/DocXMLRPCServer.py in Python
2.x, and in Lib/xmlrpc/server.py in Python 3.x. If set_server_title is
called with untrusted input, arbitrary JavaScript can be delivered to
clients that visit the http URL for this server.

CVE-2021-23336

The Python2.7 vulnerable to Web Cache Poisoning via
urllib.parse.parse_qsl and urllib.parse.parse_qs by using a vector
called parameter cloaking. When the attacker can separate query
parameters using a semicolon (;), they can cause a difference in the
interpretation of the request between the proxy (running with default
configuration) and the server. This can result in malicious requests
being cached as completely safe ones, as the proxy would usually not
see the semicolon as a separator, and therefore would not include it
in a cache key of an unkeyed parameter.

**Attention, API-change!** Please be sure your software is
working properly if it uses `urllib.parse.parse_qs` or
`urllib.parse.parse_qsl`, `cgi.parse` or
`cgi.parse_multipart`.

Earlier Python versions allowed using both ``;`` and ``&``
as query parameter separators in `urllib.parse.parse_qs` and
`urllib.parse.parse_qsl`. Due to security concerns, and to
conform with newer W3C recommendations, this has been
changed to allow only a single separator key, with ``&`` as
the default. This change also affects `cgi.parse` and
`cgi.parse_multipart` as they use the affected functions
internally. For more details, please see their respective
documentation.

For Debian 9 stretch, these problems have been fixed in version
2.7.13-2+deb9u5.

We recommend that you upgrade your python2.7 packages.

For the detailed security status of python2.7 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/python2.7

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python2.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/python2.7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"9.0", prefix:"idle-python2.7", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-dbg", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-dev", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-minimal", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-stdlib", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-testsuite", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-dbg", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-dev", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-doc", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-examples", reference:"2.7.13-2+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-minimal", reference:"2.7.13-2+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
