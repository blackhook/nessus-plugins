#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-180. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15017);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2002-1232");
  script_xref(name:"DSA", value:"180");

  script_name(english:"Debian DSA-180-1 : nis - information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Thorsten Kukuck discovered a problem in the ypserv program which is
part of the Network Information Services (NIS). A memory leak in all
versions of ypserv prior to 2.5 is remotely exploitable. When a
malicious user could request a non-existing map the server will leak
parts of an old domainname and mapname."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-180"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nis package.

This problem has been fixed in version 3.9-6.1 for the current stable
distribution (woody), in version 3.8-2.1 for the old stable
distribution (potato) and in version 3.9-6.2 for the unstable
distribution (sid)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/10/21");
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
if (deb_check(release:"2.2", prefix:"nis", reference:"3.8-2.1")) flag++;
if (deb_check(release:"3.0", prefix:"nis", reference:"3.9-6.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
