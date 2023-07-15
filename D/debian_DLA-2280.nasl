#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2280-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138529);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2018-20406", "CVE-2018-20852", "CVE-2019-10160", "CVE-2019-16056", "CVE-2019-16935", "CVE-2019-18348", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9740", "CVE-2019-9947", "CVE-2019-9948", "CVE-2020-14422", "CVE-2020-8492");
  script_xref(name:"IAVA", value:"2020-A-0340-S");

  script_name(english:"Debian DLA-2280-1 : python3.5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues were discovered in Python, an interactive
high-level object-oriented language.

CVE-2018-20406

Modules/_pickle.c has an integer overflow via a large LONG_BINPUT
value that is mishandled during a 'resize to twice the size' attempt.
This issue might cause memory exhaustion, but is only relevant if the
pickle format is used for serializing tens or hundreds of gigabytes of
data.

CVE-2018-20852

http.cookiejar.DefaultPolicy.domain_return_ok in Lib/http/cookiejar.py
does not correctly validate the domain: it can be tricked into sending
existing cookies to the wrong server. An attacker may abuse this flaw
by using a server with a hostname that has another valid hostname as a
suffix (e.g., pythonicexample.com to steal cookies for example.com).
When a program uses http.cookiejar.DefaultPolicy and tries to do an
HTTP connection to an attacker-controlled server, existing cookies can
be leaked to the attacker.

CVE-2019-5010

An exploitable denial of service vulnerability exists in the X509
certificate parser. A specially crafted X509 certificate can cause a
NULL pointer dereference, resulting in a denial of service. An
attacker can initiate or accept TLS connections using crafted
certificates to trigger this vulnerability.

CVE-2019-9636

Improper Handling of Unicode Encoding (with an incorrect netloc)
during NFKC normalization. The impact is: Information disclosure
(credentials, cookies, etc. that are cached against a given hostname).
The components are: urllib.parse.urlsplit, urllib.parse.urlparse. The
attack vector is: A specially crafted URL could be incorrectly parsed
to locate cookies or authentication data and send that information to
a different host than when parsed correctly.

CVE-2019-9740

An issue was discovered in urllib2. CRLF injection is possible if the
attacker controls a url parameter, as demonstrated by the first
argument to urllib.request.urlopen with \r\n (specifically in the
query string after a ? character) followed by an HTTP header or a
Redis command.

CVE-2019-9947

An issue was discovered in urllib2. CRLF injection is possible if the
attacker controls a url parameter, as demonstrated by the first
argument to urllib.request.urlopen with \r\n (specifically in the path
component of a URL that lacks a ? character) followed by an HTTP
header or a Redis command. This is similar to the CVE-2019-9740 query
string issue.

CVE-2019-9948

urllib supports the local_file: scheme, which makes it easier for
remote attackers to bypass protection mechanisms that blacklist file:
URIs, as demonstrated by triggering a
urllib.urlopen('local_file:///etc/passwd') call.

CVE-2019-10160

A security regression was discovered in python, which still allows an
attacker to exploit CVE-2019-9636 by abusing the user and password
parts of a URL. When an application parses user-supplied URLs to store
cookies, authentication credentials, or other kind of information, it
is possible for an attacker to provide specially crafted URLs to make
the application locate host-related information (e.g. cookies,
authentication data) and send them to a different host than where it
should, unlike if the URLs had been correctly parsed. The result of an
attack may vary based on the application.

CVE-2019-16056

The email module wrongly parses email addresses that contain multiple
@ characters. An application that uses the email module and implements
some kind of checks on the From/To headers of a message could be
tricked into accepting an email address that should be denied. An
attack may be the same as in CVE-2019-11340; however, this CVE applies
to Python more generally.

CVE-2019-16935

The documentation XML-RPC server has XSS via the server_title field.
This occurs in Lib/xmlrpc/server.py. If set_server_title is called
with untrusted input, arbitrary JavaScript can be delivered to clients
that visit the http URL for this server.

CVE-2019-18348

An issue was discovered in urllib2. CRLF injection is possible if the
attacker controls a url parameter, as demonstrated by the first
argument to urllib.request.urlopen with \r\n (specifically in the host
component of a URL) followed by an HTTP header. This is similar to the
CVE-2019-9740 query string issue and the CVE-2019-9947 path string
issue

CVE-2020-8492

Python allows an HTTP server to conduct Regular Expression Denial of
Service (ReDoS) attacks against a client because of
urllib.request.AbstractBasicAuthHandler catastrophic backtracking.

CVE-2020-14422

Lib/ipaddress.py improperly computes hash values in the IPv4Interface
and IPv6Interface classes, which might allow a remote attacker to
cause a denial of service if an application is affected by the
performance of a dictionary containing IPv4Interface or IPv6Interface
objects, and this attacker can cause many dictionary entries to be
created.

For Debian 9 stretch, these problems have been fixed in version
3.5.3-1+deb9u2.

We recommend that you upgrade your python3.5 packages.

For the detailed security status of python3.5 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/python3.5

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python3.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/python3.5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9948");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython3.5-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3.5-venv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"idle-python3.5", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5-dbg", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5-dev", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5-minimal", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5-stdlib", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpython3.5-testsuite", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-dbg", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-dev", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-doc", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-examples", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-minimal", reference:"3.5.3-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3.5-venv", reference:"3.5.3-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
