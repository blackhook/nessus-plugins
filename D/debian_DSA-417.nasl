#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-417. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15254);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2003-0961", "CVE-2003-0985");
  script_bugtraq_id(9356);
  script_xref(name:"DSA", value:"417");

  script_name(english:"Debian DSA-417-1 : linux-kernel-2.4.18-powerpc+alpha - missing boundary check");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Paul Starzetz discovered a flaw in bounds checking in mremap() in the
Linux kernel (present in version 2.4.x and 2.6.x) which may allow a
local attacker to gain root privileges. Version 2.2 is not affected by
this bug.

Andrew Morton discovered a missing boundary check for the brk system
call which can be used to craft a local root exploit."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-417"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel packages. These problems have been fixed in the
upstream version 2.4.24 as well.

For the stable distribution (woody) these problems have been fixed in
version 2.4.18-12 for the alpha architecture and in version
2.4.18-1woody3 for the powerpc architecture."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-2.4.18-1-alpha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-patch-2.4.18-powerpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/07");
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
if (deb_check(release:"3.0", prefix:"kernel-doc-2.4.18", reference:"2.4.18-14.1")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18", reference:"2.4.18-1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-generic", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-smp", reference:"2.4.18-12")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-generic", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-smp", reference:"2.4.18-11")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-newpmac", reference:"2.4.18-1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-powerpc", reference:"2.4.18-1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-powerpc-smp", reference:"2.4.18-1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-patch-2.4.18-powerpc", reference:"2.4.18-1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-source-2.4.18", reference:"2.4.18-14.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
