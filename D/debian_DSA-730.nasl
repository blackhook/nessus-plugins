#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-730. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18517);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0953");
  script_xref(name:"DSA", value:"730");

  script_name(english:"Debian DSA-730-1 : bzip2 - race condition");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Imran Ghory discovered a race condition in bzip2, a high-quality
block-sorting file compressor and decompressor. When decompressing a
file in a directory an attacker has access to, bunzip2 could be
tricked to set the file permissions to a different file the user has
permissions to."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=303300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-730"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bzip2 packages.

For the stable distribution (woody) this problem has been fixed in
version 1.0.2-1.woody2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bzip2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/17");
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
if (deb_check(release:"3.0", prefix:"bzip2", reference:"1.0.2-1.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libbz2-1.0", reference:"1.0.2-1.woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libbz2-dev", reference:"1.0.2-1.woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
