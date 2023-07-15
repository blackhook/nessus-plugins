#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1513. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31360);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-1111");
  script_xref(name:"DSA", value:"1513");

  script_name(english:"Debian DSA-1513-1 : lighttpd - information disclosure");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that lighttpd, a fast webserver with minimal memory
footprint, would display the source to CGI scripts if their execution
failed in some circumstances."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2008/dsa-1513"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lighttpd package.

For the stable distribution (etch), this problem has been fixed in
version 1.4.13-4etch5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"4.0", prefix:"lighttpd", reference:"1.4.13-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-doc", reference:"1.4.13-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-cml", reference:"1.4.13-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-magnet", reference:"1.4.13-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.13-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.13-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"lighttpd-mod-webdav", reference:"1.4.13-4etch5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
