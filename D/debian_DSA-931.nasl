#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-931. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22797);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");
  script_xref(name:"DSA", value:"931");

  script_name(english:"Debian DSA-931-1 : xpdf - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"'infamous41md' and Chris Evans discovered several heap based buffer
overflows in xpdf, the Portable Document Format (PDF) suite, that can
lead to a denial of service by crashing the application or possibly to
the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=342281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-931"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xpdf package.

For the old stable distribution (woody) these problems have been fixed
in version 1.00-3.8.

For the stable distribution (sarge) these problems have been fixed in
version 3.00-13.4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"xpdf", reference:"1.00-3.8")) flag++;
if (deb_check(release:"3.0", prefix:"xpdf-common", reference:"1.00-3.8")) flag++;
if (deb_check(release:"3.0", prefix:"xpdf-reader", reference:"1.00-3.8")) flag++;
if (deb_check(release:"3.0", prefix:"xpdf-utils", reference:"1.00-3.8")) flag++;
if (deb_check(release:"3.1", prefix:"xpdf", reference:"3.00-13.4")) flag++;
if (deb_check(release:"3.1", prefix:"xpdf-common", reference:"3.00-13.4")) flag++;
if (deb_check(release:"3.1", prefix:"xpdf-reader", reference:"3.00-13.4")) flag++;
if (deb_check(release:"3.1", prefix:"xpdf-utils", reference:"3.00-13.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
