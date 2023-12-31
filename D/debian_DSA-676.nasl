#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-676. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16380);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0074");
  script_xref(name:"DSA", value:"676");

  script_name(english:"Debian DSA-676-1 : xpcd - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Erik Sjolund discovered a buffer overflow in pcdsvgaview, an SVGA
PhotoCD viewer. xpcd-svga is part of xpcd and uses svgalib to display
graphics on the Linux console for which root permissions are required.
A malicious user could overflow a fixed-size buffer and may cause the
program to execute arbitrary code with elevated privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-676"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xpcd-svga package immediately.

For the stable distribution (woody) this problem has been fixed in
version 2.08-8woody3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xpcd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"xpcd", reference:"2.08-8woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xpcd-gimp", reference:"2.08-8woody3")) flag++;
if (deb_check(release:"3.0", prefix:"xpcd-svga", reference:"2.08-8woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
