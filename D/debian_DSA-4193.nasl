#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4193. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109588);
  script_version("1.7");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2018-10100", "CVE-2018-10101", "CVE-2018-10102");
  script_xref(name:"DSA", value:"4193");

  script_name(english:"Debian DSA-4193-1 : wordpress - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in wordpress, a web blogging
tool, which could allow remote attackers to compromise a site via
cross-site scripting, bypass restrictions or unsafe redirects. More
information can be found in the upstream advisory at
https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-mainte
nance-release/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=895034"
  );
  # https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f28948e"
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
    value:"https://www.debian.org/security/2018/dsa-4193"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 4.1+dfsg-1+deb8u17.

For the stable distribution (stretch), these problems have been fixed
in version 4.7.5+dfsg-2+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/07");
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
if (deb_check(release:"8.0", prefix:"wordpress", reference:"4.1+dfsg-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-l10n", reference:"4.1+dfsg-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentyfifteen", reference:"4.1+dfsg-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentyfourteen", reference:"4.1+dfsg-1+deb8u17")) flag++;
if (deb_check(release:"8.0", prefix:"wordpress-theme-twentythirteen", reference:"4.1+dfsg-1+deb8u17")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress", reference:"4.7.5+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-l10n", reference:"4.7.5+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyfifteen", reference:"4.7.5+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyseventeen", reference:"4.7.5+dfsg-2+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentysixteen", reference:"4.7.5+dfsg-2+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
