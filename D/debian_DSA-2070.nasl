#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2070. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47735);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-2497", "CVE-2010-2498", "CVE-2010-2499", "CVE-2010-2500", "CVE-2010-2519", "CVE-2010-2520", "CVE-2010-2527");
  script_bugtraq_id(41663);
  script_xref(name:"DSA", value:"2070");

  script_name(english:"Debian DSA-2070-1 : freetype - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Robert Swiecki discovered several vulnerabilities in the FreeType font
library, which could lead to the execution of arbitrary code if a
malformed font file is processed.

Also, several buffer overflows were found in the included demo
programs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2010/dsa-2070"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the freetype packages.

For the stable distribution (lenny), these problems have been fixed in
version 2.3.7-2+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"5.0", prefix:"freetype2-demos", reference:"2.3.7-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libfreetype6", reference:"2.3.7-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libfreetype6-dev", reference:"2.3.7-2+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
