#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1403. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27842);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-5386", "CVE-2007-5589");
  script_xref(name:"DSA", value:"1403");

  script_name(english:"Debian DSA-1403-1 : phpmyadmin - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Omer Singer of the DigiTrust Group discovered several vulnerabilities
in phpMyAdmin, an application to administrate MySQL over the WWW. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-5589
    phpMyAdmin allows a remote attacker to inject arbitrary
    web script or HTML in the context of a logged in user's
    session (cross site scripting).

  - CVE-2007-5386
    phpMyAdmin, when accessed by a browser that does not
    URL-encode requests, allows remote attackers to inject
    arbitrary web script or HTML via the query string."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2007/dsa-1403"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the phpmyadmin package.

For the old stable distribution (sarge) this problem has been fixed in
version 4:2.6.2-3sarge6.

For the stable distribution (etch) this problem has been fixed in
version 4:2.9.1.1-6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"3.1", prefix:"phpmyadmin", reference:"4:2.6.2-3sarge6")) flag++;
if (deb_check(release:"4.0", prefix:"phpmyadmin", reference:"4:2.9.1.1-6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
