#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2379. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57519);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-1528", "CVE-2011-1529");
  script_bugtraq_id(50273);
  script_xref(name:"DSA", value:"2379");

  script_name(english:"Debian DSA-2379-1 : krb5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Key Distribution Center (KDC) in Kerberos 5
crashes when processing certain crafted requests :

  - CVE-2011-1528
    When the LDAP backend is used, remote users can trigger
    a KDC daemon crash and denial of service.

  - CVE-2011-1529
    When the LDAP or Berkeley DB backend is used, remote
    users can trigger a NULL pointer dereference in the KDC
    daemon and a denial of service.

The oldstable distribution (lenny) is not affected by these problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/krb5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2012/dsa-2379"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 packages.

For the stable distribution (squeeze), these problems have been fixed
in version 1.8.3+dfsg-4squeeze5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"krb5-admin-server", reference:"1.8.3+dfsg-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-doc", reference:"1.8.3+dfsg-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-kdc", reference:"1.8.3+dfsg-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-kdc-ldap", reference:"1.8.3+dfsg-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-multidev", reference:"1.8.3+dfsg-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-pkinit", reference:"1.8.3+dfsg-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-user", reference:"1.8.3+dfsg-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libkrb5-dev", reference:"1.8.3+dfsg-4squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libkrb53", reference:"1.8.3+dfsg-4squeeze5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
