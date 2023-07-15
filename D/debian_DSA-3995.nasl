#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3995. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103757);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-13720", "CVE-2017-13722");
  script_xref(name:"DSA", value:"3995");

  script_name(english:"Debian DSA-3995-1 : libxfont - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were found in libXfont, the X11 font rasterisation
library, which could result in denial of service or memory disclosure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libxfont"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libxfont"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3995"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxfont packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1:1.5.1-1+deb8u1.

For the stable distribution (stretch), these problems have been fixed
in version 1:2.0.1-3+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxfont");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/11");
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
if (deb_check(release:"8.0", prefix:"libxfont-dev", reference:"1:1.5.1-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libxfont1", reference:"1:1.5.1-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libxfont1-dbg", reference:"1:1.5.1-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libxfont1-udeb", reference:"1:1.5.1-1+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxfont-dev", reference:"1:2.0.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxfont2", reference:"1:2.0.1-3+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxfont2-udeb", reference:"1:2.0.1-3+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
