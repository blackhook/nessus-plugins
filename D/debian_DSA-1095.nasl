#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1095. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22637);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0747", "CVE-2006-1861", "CVE-2006-2661");
  script_bugtraq_id(18034);
  script_xref(name:"DSA", value:"1095");

  script_name(english:"Debian DSA-1095-1 : freetype - integer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in the FreeType 2 font engine.
The Common vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2006-0747
    Several integer underflows have been discovered which
    could allow remote attackers to cause a denial of
    service.

  - CVE-2006-1861
    Chris Evans discovered several integer overflows that
    lead to a denial of service or could possibly even lead
    to the execution of arbitrary code.

  - CVE-2006-2493
    Several more integer overflows have been discovered
    which could possibly lead to the execution of arbitrary
    code.

  - CVE-2006-2661
    A NULL pointer dereference could cause a denial of
    service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-1861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1095"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libfreetype packages.

For the old stable distribution (woody) these problems have been fixed
in version 2.0.9-1woody1.

For the stable distribution (sarge) these problems have been fixed in
version 2.1.7-2.5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/02");
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
if (deb_check(release:"3.0", prefix:"freetype2-demos", reference:"2.0.9-1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libfreetype6", reference:"2.0.9-1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libfreetype6-dev", reference:"2.0.9-1woody1")) flag++;
if (deb_check(release:"3.1", prefix:"freetype2-demos", reference:"2.1.7-2.5")) flag++;
if (deb_check(release:"3.1", prefix:"libfreetype6", reference:"2.1.7-2.5")) flag++;
if (deb_check(release:"3.1", prefix:"libfreetype6-dev", reference:"2.1.7-2.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
