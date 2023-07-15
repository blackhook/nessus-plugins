#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1853-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126653);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-3578", "CVE-2014-3625", "CVE-2015-3192", "CVE-2015-5211", "CVE-2016-9878");
  script_bugtraq_id(68042);

  script_name(english:"Debian DLA-1853-1 : libspring-java security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerabilities have been identified in libspring-java, a modular
Java/J2EE application framework.

CVE-2014-3578

A directory traversal vulnerability that allows remote attackers to
read arbitrary files via a crafted URL.

CVE-2014-3625

A directory traversal vulnerability that allows remote attackers to
read arbitrary files via unspecified vectors, related to static
resource handling.

CVE-2015-3192

Improper processing of inline DTD declarations when DTD is not
entirely disabled, which allows remote attackers to cause a denial of
service (memory consumption and out-of-memory errors) via a crafted
XML file.

CVE-2015-5211

Reflected File Download (RFD) attack vulnerability, which allows a
malicious user to craft a URL with a batch script extension that
results in the response being downloaded rather than rendered and also
includes some input reflected in the response.

CVE-2016-9878

Improper path sanitization in ResourceServlet, which allows directory
traversal attacks.

For Debian 8 'Jessie', these problems have been fixed in version
3.0.6.RELEASE-17+deb8u1.

We recommend that you upgrade your libspring-java packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libspring-java"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-aop-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-beans-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-context-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-context-support-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-core-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-expression-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-instrument-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-jdbc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-jms-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-orm-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-oxm-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-test-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-transaction-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-web-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-web-portlet-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspring-web-servlet-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libspring-aop-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-beans-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-context-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-context-support-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-core-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-expression-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-instrument-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-jdbc-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-jms-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-orm-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-oxm-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-test-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-transaction-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-web-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-web-portlet-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libspring-web-servlet-java", reference:"3.0.6.RELEASE-17+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
