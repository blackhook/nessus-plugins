#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4321. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118179);
  script_version("1.5");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2017-10794", "CVE-2017-10799", "CVE-2017-10800", "CVE-2017-11102", "CVE-2017-11139", "CVE-2017-11140", "CVE-2017-11403", "CVE-2017-11636", "CVE-2017-11637", "CVE-2017-11638", "CVE-2017-11641", "CVE-2017-11642", "CVE-2017-11643", "CVE-2017-11722", "CVE-2017-12935", "CVE-2017-12936", "CVE-2017-12937", "CVE-2017-13063", "CVE-2017-13064", "CVE-2017-13065", "CVE-2017-13134", "CVE-2017-13737", "CVE-2017-13775", "CVE-2017-13776", "CVE-2017-13777", "CVE-2017-14314", "CVE-2017-14504", "CVE-2017-14733", "CVE-2017-14994", "CVE-2017-14997", "CVE-2017-15238", "CVE-2017-15277", "CVE-2017-15930", "CVE-2017-16352", "CVE-2017-16353", "CVE-2017-16545", "CVE-2017-16547", "CVE-2017-16669", "CVE-2017-17498", "CVE-2017-17500", "CVE-2017-17501", "CVE-2017-17502", "CVE-2017-17503", "CVE-2017-17782", "CVE-2017-17783", "CVE-2017-17912", "CVE-2017-17913", "CVE-2017-17915", "CVE-2017-18219", "CVE-2017-18220", "CVE-2017-18229", "CVE-2017-18230", "CVE-2017-18231", "CVE-2018-5685", "CVE-2018-6799", "CVE-2018-9018");
  script_xref(name:"DSA", value:"4321");

  script_name(english:"Debian DSA-4321-1 : graphicsmagick - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in GraphicsMagick, a set
of command-line applications to manipulate image files, which could
result in denial of service or the execution of arbitrary code if
malformed image files are processed."
  );
  # https://security-tracker.debian.org/tracker/source-package/graphicsmagick
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e247f871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/graphicsmagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4321"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the graphicsmagick packages.

For the stable distribution (stretch), these problems have been fixed
in version 1.3.30+hg15796-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"graphicsmagick", reference:"1.3.30+hg15796-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"graphicsmagick-dbg", reference:"1.3.30+hg15796-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"graphicsmagick-imagemagick-compat", reference:"1.3.30+hg15796-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"graphicsmagick-libmagick-dev-compat", reference:"1.3.30+hg15796-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgraphics-magick-perl", reference:"1.3.30+hg15796-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgraphicsmagick++-q16-12", reference:"1.3.30+hg15796-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgraphicsmagick++1-dev", reference:"1.3.30+hg15796-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgraphicsmagick-q16-3", reference:"1.3.30+hg15796-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgraphicsmagick1-dev", reference:"1.3.30+hg15796-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
