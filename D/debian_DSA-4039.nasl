#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4039. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104645);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-16853");
  script_xref(name:"DSA", value:"4039");

  script_name(english:"Debian DSA-4039-1 : opensaml2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Rod Widdowson of Steading System Software LLP discovered a coding
error in the OpenSAML library, causing the DynamicMetadataProvider
class to fail configuring itself with the filters provided and
omitting whatever checks they are intended to perform.

See https://shibboleth.net/community/advisories/secadv_20171115.txt
for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=881856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://shibboleth.net/community/advisories/secadv_20171115.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/opensaml2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/opensaml2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4039"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the opensaml2 packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 2.5.3-2+deb8u2.

For the stable distribution (stretch), this problem has been fixed in
version 2.6.0-4+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensaml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libsaml2-dev", reference:"2.5.3-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsaml2-doc", reference:"2.5.3-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsaml8", reference:"2.5.3-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"opensaml2-schemas", reference:"2.5.3-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"opensaml2-tools", reference:"2.5.3-2+deb8u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsaml2-dev", reference:"2.6.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsaml2-doc", reference:"2.6.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libsaml9", reference:"2.6.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"opensaml2-schemas", reference:"2.6.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"opensaml2-tools", reference:"2.6.0-4+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
