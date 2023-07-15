#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4079. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105623);
  script_version("3.8");
  script_cvs_date("Date: 2019/03/15 10:28:27");

  script_cve_id("CVE-2017-14517", "CVE-2017-14518", "CVE-2017-14519", "CVE-2017-14520", "CVE-2017-14975", "CVE-2017-14976", "CVE-2017-14977", "CVE-2017-15565", "CVE-2017-9406", "CVE-2017-9408", "CVE-2017-9775", "CVE-2017-9776", "CVE-2017-9865");
  script_xref(name:"DSA", value:"4079");

  script_name(english:"Debian DSA-4079-1 : poppler - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the poppler PDF rendering
library, which could result in denial of service or the execution of
arbitrary code if a malformed PDF file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/poppler"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/poppler"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/poppler"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4079"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the poppler packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 0.26.5-2+deb8u2.

For the stable distribution (stretch), these problems have been fixed
in version 0.48.0-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"gir1.2-poppler-0.18", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-cpp-dev", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-cpp0", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-dev", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-glib-dev", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-glib-doc", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-glib8", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-private-dev", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt4-4", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt4-dev", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt5-1", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler-qt5-dev", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpoppler46", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"poppler-dbg", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"poppler-utils", reference:"0.26.5-2+deb8u2")) flag++;
if (deb_check(release:"9.0", prefix:"gir1.2-poppler-0.18", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler-cpp-dev", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler-cpp0v5", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler-dev", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler-glib-dev", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler-glib-doc", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler-glib8", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler-private-dev", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler-qt4-4", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler-qt4-dev", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler-qt5-1", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler-qt5-dev", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoppler64", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"poppler-dbg", reference:"0.48.0-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"poppler-utils", reference:"0.48.0-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
