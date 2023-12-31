#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-871. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22737);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2958");
  script_xref(name:"DSA", value:"871");

  script_name(english:"Debian DSA-871-2 : libgda2 - format string");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Steve Kemp discovered two format string vulnerabilities in libgda2,
the GNOME Data Access library for GNOME2, which may lead to the
execution of arbitrary code in programs that use this library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-871"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgda2 packages.

The old stable distribution (woody) is not affected by these problems.

For the stable distribution (sarge) these problems have been fixed in
version 1.2.1-2sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgda2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/25");
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
if (deb_check(release:"3.1", prefix:"gda2-freetds", reference:"1.2.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gda2-mysql", reference:"1.2.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gda2-odbc", reference:"1.2.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gda2-postgres", reference:"1.2.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"gda2-sqlite", reference:"1.2.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgda2-3", reference:"1.2.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgda2-3-dbg", reference:"1.2.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgda2-common", reference:"1.2.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgda2-dev", reference:"1.2.1-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libgda2-doc", reference:"1.2.1-2sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
