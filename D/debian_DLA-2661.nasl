#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2661-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149518);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2017-9735", "CVE-2018-12536", "CVE-2019-10241", "CVE-2019-10247", "CVE-2020-27216");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Debian DLA-2661-1 : jetty9 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in jetty, a Java servlet
engine and webserver. An attacker may reveal cryptographic credentials
such as passwords to a local user, disclose installation paths, hijack
user sessions or tamper with collocated webapps.

CVE-2017-9735

Jetty is prone to a timing channel in util/security/Password.java,
which makes it easier for remote attackers to obtain access by
observing elapsed times before rejection of incorrect passwords.

CVE-2018-12536

On webapps deployed using default Error Handling, when an
intentionally bad query arrives that doesn't match a dynamic
url-pattern, and is eventually handled by the DefaultServlet's static
file serving, the bad characters can trigger a
java.nio.file.InvalidPathException which includes the full path to the
base resource directory that the DefaultServlet and/or webapp is
using. If this InvalidPathException is then handled by the default
Error Handler, the InvalidPathException message is included in the
error response, revealing the full server path to the requesting
system.

CVE-2019-10241

The server is vulnerable to XSS conditions if a remote client USES a
specially formatted URL against the DefaultServlet or ResourceHandler
that is configured for showing a Listing of directory contents.

CVE-2019-10247

The server running on any OS and Jetty version combination will reveal
the configured fully qualified directory base resource location on the
output of the 404 error for not finding a Context that matches the
requested path. The default server behavior on jetty-distribution and
jetty-home will include at the end of the Handler tree a
DefaultHandler, which is responsible for reporting this 404 error, it
presents the various configured contexts as HTML for users to click
through to. This produced HTML includes output that contains the
configured fully qualified directory base resource location for each
context.

CVE-2020-27216

On Unix like systems, the system's temporary directory is shared
between all users on that system. A collocated user can observe the
process of creating a temporary sub directory in the shared temporary
directory and race to complete the creation of the temporary
subdirectory. If the attacker wins the race then they will have read
and write permission to the subdirectory used to unpack web
applications, including their WEB-INF/lib jar files and JSP files. If
any code is ever executed out of this temporary directory, this can
lead to a local privilege escalation vulnerability.

This update also includes several other bug fixes and improvements.
For more information please refer to the upstream changelog file.

For Debian 9 stretch, these problems have been fixed in version
9.2.30-0+deb9u1.

We recommend that you upgrade your jetty9 packages.

For the detailed security status of jetty9 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/jetty9

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/jetty9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/jetty9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10247");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jetty9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjetty9-extra-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjetty9-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"jetty9", reference:"9.2.30-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libjetty9-extra-java", reference:"9.2.30-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libjetty9-java", reference:"9.2.30-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
