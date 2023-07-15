#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4090. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106109);
  script_version("3.6");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-16510", "CVE-2017-17091", "CVE-2017-17092", "CVE-2017-17093", "CVE-2017-17094", "CVE-2017-9066");
  script_xref(name:"DSA", value:"4090");

  script_name(english:"Debian DSA-4090-1 : wordpress - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Wordpress, a web blogging
tool. They allowed remote attackers to perform SQL injections and
various Cross-Side Scripting (XSS) and Server-Side Request Forgery
(SSRF) attacks, as well as bypass some access restrictions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=862816"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=883314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=880528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4090"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 4.1+dfsg-1+deb8u16.

For the stable distribution (stretch), these problems have been fixed
in version 4.7.5+dfsg-2+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"wordpress", reference:"4.1+dfsg-1+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-l10n", reference:"4.1+dfsg-1+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentyfifteen", reference:"4.1+dfsg-1+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentyfourteen", reference:"4.1+dfsg-1+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentythirteen", reference:"4.1+dfsg-1+deb8u16")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress", reference:"4.7.5+dfsg-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-l10n", reference:"4.7.5+dfsg-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyfifteen", reference:"4.7.5+dfsg-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyseventeen", reference:"4.7.5+dfsg-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentysixteen", reference:"4.7.5+dfsg-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
