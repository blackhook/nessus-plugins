#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4265. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111538);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_xref(name:"DSA", value:"4265");

  script_name(english:"Debian DSA-4265-1 : xml-security-c - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Apache XML Security for C++ library
performed insufficient validation of KeyInfo hints, which could result
in denial of service via NULL pointer dereferences when processing
malformed XML data."
  );
  # https://security-tracker.debian.org/tracker/source-package/xml-security-c
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1cb1c698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/xml-security-c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4265"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xml-security-c packages.

For the stable distribution (stretch), this problem has been fixed in
version 1.7.3-4+deb9u1."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xml-security-c");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libxml-security-c-dev", reference:"1.7.3-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxml-security-c17v5", reference:"1.7.3-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"xml-security-c-utils", reference:"1.7.3-4+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
