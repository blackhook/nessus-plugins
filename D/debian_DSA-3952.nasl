#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3952. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102685);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-0663", "CVE-2017-7375", "CVE-2017-7376", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050");
  script_xref(name:"DSA", value:"3952");

  script_name(english:"Debian DSA-3952-1 : libxml2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in libxml2, a library
providing support to read, modify and write XML and HTML files. A
remote attacker could provide a specially crafted XML or HTML file
that, when processed by an application using libxml2, would cause a
denial-of-service against the application, information leaks, or
potentially, the execution of arbitrary code with the privileges of
the user running the application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=863018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=863019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=863021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=863022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=870865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=870867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=870870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libxml2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/libxml2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3952"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libxml2 packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 2.9.1+dfsg1-5+deb8u5.

For the stable distribution (stretch), these problems have been fixed
in version 2.9.4+dfsg1-2.2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");
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
if (deb_check(release:"8.0", prefix:"libxml2", reference:"2.9.1+dfsg1-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libxml2-dbg", reference:"2.9.1+dfsg1-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libxml2-dev", reference:"2.9.1+dfsg1-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libxml2-doc", reference:"2.9.1+dfsg1-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libxml2-utils", reference:"2.9.1+dfsg1-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libxml2-utils-dbg", reference:"2.9.1+dfsg1-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"python-libxml2", reference:"2.9.1+dfsg1-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"python-libxml2-dbg", reference:"2.9.1+dfsg1-5+deb8u5")) flag++;
if (deb_check(release:"9.0", prefix:"libxml2", reference:"2.9.4+dfsg1-2.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxml2-dbg", reference:"2.9.4+dfsg1-2.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxml2-dev", reference:"2.9.4+dfsg1-2.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxml2-doc", reference:"2.9.4+dfsg1-2.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxml2-utils", reference:"2.9.4+dfsg1-2.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libxml2-utils-dbg", reference:"2.9.4+dfsg1-2.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-libxml2", reference:"2.9.4+dfsg1-2.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-libxml2-dbg", reference:"2.9.4+dfsg1-2.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-libxml2", reference:"2.9.4+dfsg1-2.2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-libxml2-dbg", reference:"2.9.4+dfsg1-2.2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
