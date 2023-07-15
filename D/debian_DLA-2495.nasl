#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2495-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144343);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-17527");
  script_xref(name:"IAVA", value:"2020-A-0570-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DLA-2495-1 : tomcat8 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that Apache Tomcat from 8.5.0 to 8.5.59 could re-use
an HTTP request header value from the previous stream received on an
HTTP/2 connection for the request associated with the subsequent
stream. While this would most likely lead to an error and the closure
of the HTTP/2 connection, it is possible that information could leak
between requests.

For Debian 9 stretch, this problem has been fixed in version
8.5.54-0+deb9u5.

We recommend that you upgrade your tomcat8 packages.

For the detailed security status of tomcat8 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/tomcat8

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/tomcat8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/tomcat8"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet3.1-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet3.1-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat8-embed-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat8-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat8-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/17");
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
if (deb_check(release:"9.0", prefix:"libservlet3.1-java", reference:"8.5.54-0+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libservlet3.1-java-doc", reference:"8.5.54-0+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libtomcat8-embed-java", reference:"8.5.54-0+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libtomcat8-java", reference:"8.5.54-0+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8", reference:"8.5.54-0+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8-admin", reference:"8.5.54-0+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8-common", reference:"8.5.54-0+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8-docs", reference:"8.5.54-0+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8-examples", reference:"8.5.54-0+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"tomcat8-user", reference:"8.5.54-0+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
