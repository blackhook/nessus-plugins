#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4204. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109925);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2017-10995", "CVE-2017-11533", "CVE-2017-11535", "CVE-2017-11639", "CVE-2017-13143", "CVE-2017-17504", "CVE-2017-17879", "CVE-2018-5248");
  script_xref(name:"DSA", value:"4204");

  script_name(english:"Debian DSA-4204-1 : imagemagick - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes several vulnerabilities in imagemagick, a graphical
software suite. Various memory handling problems or issues about
incomplete input sanitizing would result in denial of service or
memory disclosure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=867748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=870012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=870065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=885125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=885340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=886588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/imagemagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/imagemagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4204"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imagemagick packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 8:6.8.9.9-5+deb8u12."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/21");
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
if (deb_check(release:"8.0", prefix:"imagemagick", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-6.q16", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-common", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-dbg", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-doc", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libimage-magick-perl", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libimage-magick-q16-perl", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6-headers", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6.q16-5", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6.q16-dev", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-dev", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6-arch-config", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6-headers", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-2", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-2-extra", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-dev", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-dev", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6-headers", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6.q16-2", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6.q16-dev", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-dev", reference:"8:6.8.9.9-5+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"perlmagick", reference:"8:6.8.9.9-5+deb8u12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
