#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-278. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15115);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2003-0161");
  script_bugtraq_id(7230);
  script_xref(name:"CERT", value:"897604");
  script_xref(name:"DSA", value:"278");

  script_name(english:"Debian DSA-278-1 : sendmail - char-to-int conversion");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Michal Zalewski discovered a buffer overflow, triggered by a char to
int conversion, in the address parsing code in sendmail, a widely used
powerful, efficient, and scalable mail transport agent. This problem
is potentially remotely exploitable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-278"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sendmail packages.

For the stable distribution (woody) this problem has been fixed in
version 8.12.3-6.3.

For the old stable distribution (potato) this problem has been fixed
in version 8.9.3-26."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sendmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/29");
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
if (deb_check(release:"2.2", prefix:"sendmail", reference:"8.9.3-26")) flag++;
if (deb_check(release:"3.0", prefix:"libmilter-dev", reference:"8.12.3-6.3")) flag++;
if (deb_check(release:"3.0", prefix:"sendmail", reference:"8.12.3-6.3")) flag++;
if (deb_check(release:"3.0", prefix:"sendmail-doc", reference:"8.12.3-6.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
