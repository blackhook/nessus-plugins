#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1837. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44702);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-1189");
  script_bugtraq_id(31602);
  script_xref(name:"DSA", value:"1837");

  script_name(english:"Debian DSA-1837-1 : dbus - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the dbus_signature_validate function in dbus, a
simple interprocess messaging system, is prone to a denial of service
attack. This issue was caused by an incorrect fix for DSA-1658-1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=532720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2009/dsa-1837"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dbus packages.

For the stable distribution (lenny), this problem has been fixed in
version 1.2.1-5+lenny1.

For the oldstable distribution (etch), this problem has been fixed in
version 1.0.2-1+etch3.

Packages for ia64 and s390 will be released once they are available."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dbus");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/18");
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
if (deb_check(release:"4.0", prefix:"dbus", reference:"1.0.2-1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"dbus-1-doc", reference:"1.0.2-1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"dbus-1-utils", reference:"1.0.2-1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libdbus-1-3", reference:"1.0.2-1+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libdbus-1-dev", reference:"1.0.2-1+etch3")) flag++;
if (deb_check(release:"5.0", prefix:"dbus", reference:"1.2.1-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"dbus-1-doc", reference:"1.2.1-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"dbus-x11", reference:"1.2.1-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libdbus-1-3", reference:"1.2.1-5+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libdbus-1-dev", reference:"1.2.1-5+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
