#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-996-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100941);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-5664");

  script_name(english:"Debian DLA-996-1 : tomcat7 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The error page mechanism of the Java Servlet Specification requires
that, when an error occurs and an error page is configured for the
error that occurred, the original request and response are forwarded
to the error page. This means that the request is presented to the
error page with the original HTTP method. If the error page is a
static file, expected behaviour is to serve content of the file as if
processing a GET request, regardless of the actual HTTP method. The
Default Servlet in Apache Tomcat did not do this. Depending on the
original request this could lead to unexpected and undesirable results
for static error pages including, if the DefaultServlet is configured
to permit writes, the replacement or removal of the custom error page.

For Debian 7 'Wheezy', these problems have been fixed in version
7.0.28-4+deb7u14.

We recommend that you upgrade your tomcat7 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tomcat7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet3.0-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet3.0-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat7-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libservlet3.0-java", reference:"7.0.28-4+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libservlet3.0-java-doc", reference:"7.0.28-4+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libtomcat7-java", reference:"7.0.28-4+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7", reference:"7.0.28-4+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-admin", reference:"7.0.28-4+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-common", reference:"7.0.28-4+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-docs", reference:"7.0.28-4+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-examples", reference:"7.0.28-4+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-user", reference:"7.0.28-4+deb7u14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
