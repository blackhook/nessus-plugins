#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2337-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139757);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2018-20852", "CVE-2019-10160", "CVE-2019-16056", "CVE-2019-20907", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9740", "CVE-2019-9947", "CVE-2019-9948");
  script_xref(name:"IAVA", value:"2020-A-0340-S");

  script_name(english:"Debian DLA-2337-1 : python2.7 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities were discovered in Python2.7, an interactive
high-level object-oriented language.

CVE-2018-20852

By using a malicious server an attacker might steal cookies that are
meant for other domains.

CVE-2019-5010

NULL pointer dereference using a specially crafted X509 certificate.

CVE-2019-9636

Improper Handling of Unicode Encoding (with an incorrect netloc)
during NFKC normalization resulting in information disclosure
(credentials, cookies, etc. that are cached against a given hostname).
A specially crafted URL could be incorrectly parsed to locate cookies
or authentication data and send that information to a different host
than when parsed correctly.

CVE-2019-9740

An issue was discovered in urllib2 where CRLF injection is possible if
the attacker controls a url parameter, as demonstrated by the first
argument to urllib.request.urlopen with \r\n (specifically in the
query string after a ? character) followed by an HTTP header or a
Redis command.

CVE-2019-9947

An issue was discovered in urllib2 where CRLF injection is possible if
the attacker controls a url parameter, as demonstrated by the first
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

A security regression of CVE-2019-9636 was discovered which still
allows an attacker to exploit CVE-2019-9636 by abusing the user and
password parts of a URL. When an application parses user-supplied URLs
to store cookies, authentication credentials, or other kind of
information, it is possible for an attacker to provide specially
crafted URLs to make the application locate host-related information
(e.g. cookies, authentication data) and send them to a different host
than where it should, unlike if the URLs had been correctly parsed.
The result of an attack may vary based on the application.

CVE-2019-16056

The email module wrongly parses email addresses that contain multiple
@ characters. An application that uses the email module and implements
some kind of checks on the From/To headers of a message could be
tricked into accepting an email address that should be denied.

CVE-2019-20907

Opening a crafted tar file could result in an infinite loop due to
missing header validation.

For Debian 9 stretch, these problems have been fixed in version
2.7.13-2+deb9u4.

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
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00034.html"
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9948");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/24");
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
if (deb_check(release:"9.0", prefix:"idle-python2.7", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-dbg", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-dev", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-minimal", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-stdlib", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libpython2.7-testsuite", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-dbg", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-dev", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-doc", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-examples", reference:"2.7.13-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python2.7-minimal", reference:"2.7.13-2+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
