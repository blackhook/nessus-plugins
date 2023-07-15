#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2289. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55769);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"DSA", value:"2289");

  script_name(english:"Debian DSA-2289-1 : typo3-src - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the TYPO3 web
content management framework: cross-site scripting, information
disclosure, authentication delay bypass, and arbitrary file deletion.
More details can be found in the Typo3 security advisory:
TYPO3-CORE-SA-2011-001."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=635937"
  );
  # http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2011-001/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7100534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/typo3-src"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2011/dsa-2289"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the typo3-src packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 4.2.5-1+lenny8.

For the stable distribution (squeeze), these problems have been fixed
in version 4.3.9+dfsg1-1+squeeze1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:typo3-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"5.0", prefix:"typo3-src", reference:"4.2.5-1+lenny8")) flag++;
if (deb_check(release:"6.0", prefix:"typo3", reference:"4.3.9+dfsg1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"typo3-database", reference:"4.3.9+dfsg1-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"typo3-src-4.3", reference:"4.3.9+dfsg1-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
