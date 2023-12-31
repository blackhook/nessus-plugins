#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1688. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35225);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-2380", "CVE-2008-2667");
  script_xref(name:"DSA", value:"1688");

  script_name(english:"Debian DSA-1688-1 : courier-authlib - SQL injection");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two SQL injection vulnerabilities have been found in courier-authlib,
the courier authentification library. The MySQL database interface
used insufficient escaping mechanisms when constructing SQL
statements, leading to SQL injection vulnerabilities if certain
charsets are used (CVE-2008-2380 ). A similar issue affects the
PostgreSQL database interface (CVE-2008-2667 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2008/dsa-1688"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the courier-authlib packages.

For the stable distribution (etch), these problems have been fixed in
version 0.58-4+etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier-authlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/21");
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
if (deb_check(release:"4.0", prefix:"courier-authdaemon", reference:"0.58-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"courier-authlib", reference:"0.58-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"courier-authlib-dev", reference:"0.58-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"courier-authlib-ldap", reference:"0.58-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"courier-authlib-mysql", reference:"0.58-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"courier-authlib-pipe", reference:"0.58-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"courier-authlib-postgresql", reference:"0.58-4+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"courier-authlib-userdb", reference:"0.58-4+etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
