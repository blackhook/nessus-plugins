#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-224. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15061);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2002-1158", "CVE-2002-1159");
  script_bugtraq_id(6351, 6354);
  script_xref(name:"DSA", value:"224");

  script_name(english:"Debian DSA-224-1 : canna - buffer overflow and more");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in canna, a Japanese
input system. The Common Vulnerabilities and Exposures (CVE) project
identified the following vulnerabilities :

  - CAN-2002-1158 (BugTraq Id 6351): 'hsj' of Shadow Penguin
    Security discovered a heap overflow vulnerability in the
    irw_through function in canna server.
  - CAN-2002-1159 (BugTraq Id 6354): Shinra Aida of the
    Canna project discovered that canna does not properly
    validate requests, which allows remote attackers to
    cause a denial of service or information leak."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-224"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the canna packages.

For the current stable distribution (woody) these problems have been
fixed in version 3.5b2-46.2.


For the old stable distribution (potato) these problems have been
fixed in version 3.5b2-25.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:canna");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"canna", reference:"3.5b2-25.2")) flag++;
if (deb_check(release:"2.2", prefix:"canna-utils", reference:"3.5b2-25.2")) flag++;
if (deb_check(release:"2.2", prefix:"libcanna1g", reference:"3.5b2-25.2")) flag++;
if (deb_check(release:"2.2", prefix:"libcanna1g-dev", reference:"3.5b2-25.2")) flag++;
if (deb_check(release:"3.0", prefix:"canna", reference:"3.5b2-46.2")) flag++;
if (deb_check(release:"3.0", prefix:"canna-utils", reference:"3.5b2-46.2")) flag++;
if (deb_check(release:"3.0", prefix:"libcanna1g", reference:"3.5b2-46.2")) flag++;
if (deb_check(release:"3.0", prefix:"libcanna1g-dev", reference:"3.5b2-46.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
