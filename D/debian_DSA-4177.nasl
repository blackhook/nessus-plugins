#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4177. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109219);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-12122", "CVE-2017-14440", "CVE-2017-14441", "CVE-2017-14442", "CVE-2017-14448", "CVE-2017-14449", "CVE-2017-14450", "CVE-2017-2887", "CVE-2018-3837", "CVE-2018-3838", "CVE-2018-3839");
  script_xref(name:"DSA", value:"4177");

  script_name(english:"Debian DSA-4177-1 : libsdl2-image - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the image loading
library for Simple DirectMedia Layer 2, which could result in denial
of service or the execution of arbitrary code if malformed image files
are opened."
  );
  # https://security-tracker.debian.org/tracker/source-package/libsdl2-image
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc606966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libsdl2-image"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libsdl2-image"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4177"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libsdl2-image packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 2.0.0+dfsg-3+deb8u1.

For the stable distribution (stretch), these problems have been fixed
in version 2.0.1+dfsg-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsdl2-image");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/23");
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
if (deb_check(release:"8.0", prefix:"libsdl2-image-2.0-0", reference:"2.0.0+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsdl2-image-dbg", reference:"2.0.0+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsdl2-image-dev", reference:"2.0.0+dfsg-3+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsdl2-image-2.0-0", reference:"2.0.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsdl2-image-dbg", reference:"2.0.1+dfsg-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsdl2-image-dev", reference:"2.0.1+dfsg-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
