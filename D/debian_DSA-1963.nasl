#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1963. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44828);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-3602");
  script_xref(name:"DSA", value:"1963");

  script_name(english:"Debian DSA-1963-1 : unbound - cryptographic implementation error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Unbound, a DNS resolver, does not properly
check cryptographic signatures on NSEC3 records. As a result, zones
signed with the NSEC3 variant of DNSSEC lose their cryptographic
protection. (An attacker would still have to carry out an ordinary
cache poisoning attack to add bad data to the cache.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2009/dsa-1963"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the unbound package.

The old stable distribution (etch) does not contain an unbound
package.

For the stable distribution (lenny), this problem has been fixed in
version 1.0.2-1+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
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
if (deb_check(release:"5.0", prefix:"libunbound-dev", reference:"1.0.2-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libunbound0", reference:"1.0.2-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"unbound", reference:"1.0.2-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"unbound-host", reference:"1.0.2-1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
