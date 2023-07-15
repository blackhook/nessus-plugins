#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3997. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103793);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-14718", "CVE-2017-14719", "CVE-2017-14720", "CVE-2017-14721", "CVE-2017-14722", "CVE-2017-14723", "CVE-2017-14724", "CVE-2017-14725", "CVE-2017-14726", "CVE-2017-14990");
  script_xref(name:"DSA", value:"3997");

  script_name(english:"Debian DSA-3997-1 : wordpress - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Wordpress, a web blogging
tool. They would allow remote attackers to exploit path-traversal
issues, perform SQL injections and various cross-site scripting
attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=876274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=877629"
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
    value:"https://www.debian.org/security/2017/dsa-3997"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 4.1+dfsg-1+deb8u15.

For the stable distribution (stretch), these problems have been fixed
in version 4.7.5+dfsg-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/12");
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
if (deb_check(release:"8.0", prefix:"wordpress", reference:"4.1+dfsg-1+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-l10n", reference:"4.1+dfsg-1+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentyfifteen", reference:"4.1+dfsg-1+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentyfourteen", reference:"4.1+dfsg-1+deb8u15")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentythirteen", reference:"4.1+dfsg-1+deb8u15")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress", reference:"4.7.5+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-l10n", reference:"4.7.5+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyfifteen", reference:"4.7.5+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyseventeen", reference:"4.7.5+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentysixteen", reference:"4.7.5+dfsg-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
