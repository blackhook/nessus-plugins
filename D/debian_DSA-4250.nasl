#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4250. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111173);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/08");

  script_cve_id("CVE-2018-12895");
  script_xref(name:"DSA", value:"4250");

  script_name(english:"Debian DSA-4250-1 : wordpress - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability was discovered in Wordpress, a web blogging tool. It
allowed remote attackers with specific roles to execute arbitrary
code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=902876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/wordpress"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4250"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the wordpress packages.

For the stable distribution (stretch), this problem has been fixed in
version 4.7.5+dfsg-2+deb9u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"wordpress", reference:"4.7.5+dfsg-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-l10n", reference:"4.7.5+dfsg-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyfifteen", reference:"4.7.5+dfsg-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyseventeen", reference:"4.7.5+dfsg-2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentysixteen", reference:"4.7.5+dfsg-2+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
