#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4074. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105489);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-12877", "CVE-2017-16546", "CVE-2017-17499", "CVE-2017-17504", "CVE-2017-17879");
  script_xref(name:"DSA", value:"4074");

  script_name(english:"Debian DSA-4074-1 : imagemagick - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes several vulnerabilities in imagemagick: Various
memory handling problems and cases of missing or incomplete input
sanitising may result in denial of service, memory disclosure or the
execution of arbitrary code if malformed image files are processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/imagemagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/imagemagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4074"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imagemagick packages.

For the stable distribution (stretch), these problems have been fixed
in version 8:6.9.7.4+dfsg-11+deb9u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/29");
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
if (deb_check(release:"9.0", prefix:"imagemagick", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6-common", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6-doc", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6.q16", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6.q16hdri", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-common", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-doc", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libimage-magick-perl", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libimage-magick-q16-perl", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libimage-magick-q16hdri-perl", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6-headers", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16-7", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16-dev", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16hdri-7", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16hdri-dev", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-dev", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6-arch-config", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6-headers", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16-3", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16-3-extra", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16-dev", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16hdri-3", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16hdri-3-extra", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16hdri-dev", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-dev", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6-headers", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16-3", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16-dev", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16hdri-3", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16hdri-dev", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-dev", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"perlmagick", reference:"8:6.9.7.4+dfsg-11+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
