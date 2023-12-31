#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-976. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22842);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0224");
  script_xref(name:"DSA", value:"976");

  script_name(english:"Debian DSA-976-1 : libast - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Johnny Mast discovered a buffer overflow in libast, the library of
assorted spiffy things, that can lead to the execution of arbitrary
code. This library is used by eterm which is installed setgid uid
which leads to a vulnerability to alter the utmp file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-976"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libast packages.

For the old stable distribution (woody) this problem has been fixed in
version 0.4-3woody2.

For the stable distribution (sarge) this problem has been fixed in
version 0.6-0pre2003010606sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libast1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/23");
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
if (deb_check(release:"3.0", prefix:"libast1", reference:"0.4-3woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libast1-dev", reference:"0.4-3woody2")) flag++;
if (deb_check(release:"3.1", prefix:"libast2", reference:"0.6-0pre2003010606sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libast2-dev", reference:"0.6-0pre2003010606sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
