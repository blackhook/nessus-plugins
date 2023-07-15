#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4083. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105754);
  script_version("3.4");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2017-1000472");
  script_xref(name:"DSA", value:"4083");

  script_name(english:"Debian DSA-4083-1 : poco - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stephan Zeisberg discovered that poco, a collection of open source C++
class libraries, did not correctly validate file paths in ZIP
archives. An attacker could leverage this flaw to create or overwrite
arbitrary files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/poco"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/poco"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/poco"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4083"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the poco packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 1.3.6p1-5+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1.7.6+dfsg1-5+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poco");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");
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
if (deb_check(release:"8.0", prefix:"libpoco-dev", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpococrypto9", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpococrypto9-dbg", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocodata9", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocodata9-dbg", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocofoundation9", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocofoundation9-dbg", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocomysql9", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocomysql9-dbg", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoconet9", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoconet9-dbg", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoconetssl9", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpoconetssl9-dbg", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocoodbc9", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocoodbc9-dbg", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocosqlite9", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocosqlite9-dbg", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocoutil9", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocoutil9-dbg", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocoxml9", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocoxml9-dbg", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocozip9", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libpocozip9-dbg", reference:"1.3.6p1-5+deb8u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoco-dev", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpococrypto46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpocodata46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpocodatamysql46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpocodataodbc46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpocodatasqlite46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpocofoundation46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpocomongodb46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoconet46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpoconetssl46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpocoutil46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpocoxml46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpocozip46", reference:"1.7.6+dfsg1-5+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
