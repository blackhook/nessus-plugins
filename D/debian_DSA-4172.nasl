#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4172. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109047);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-6797", "CVE-2018-6798", "CVE-2018-6913");
  script_xref(name:"DSA", value:"4172");

  script_name(english:"Debian DSA-4172-1 : perl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in the implementation of the
Perl programming language. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2018-6797
    Brian Carpenter reported that a crafted regular
    expression could cause a heap buffer write overflow,
    with control over the bytes written.

  - CVE-2018-6798
    Nguyen Duc Manh reported that matching a crafted locale
    dependent regular expression can cause a heap-based
    buffer over-read and potentially information disclosure.

  - CVE-2018-6913
    GwanYeong Kim reported that 'pack()' could cause a heap
    buffer write overflow with a large item count."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4172"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 5.20.2-3+deb8u10. The oldstable distribution (jessie)
update contains only a fix for CVE-2018-6913.

For the stable distribution (stretch), these problems have been fixed
in version 5.24.1-3+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/16");
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
if (deb_check(release:"8.0", prefix:"libperl-dev", reference:"5.20.2-3+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libperl5.20", reference:"5.20.2-3+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"perl", reference:"5.20.2-3+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"perl-base", reference:"5.20.2-3+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"perl-debug", reference:"5.20.2-3+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"perl-doc", reference:"5.20.2-3+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"perl-modules", reference:"5.20.2-3+deb8u10")) flag++;
if (deb_check(release:"9.0", prefix:"libperl-dev", reference:"5.24.1-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libperl5.24", reference:"5.24.1-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"perl", reference:"5.24.1-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"perl-base", reference:"5.24.1-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"perl-debug", reference:"5.24.1-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"perl-doc", reference:"5.24.1-3+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"perl-modules-5.24", reference:"5.24.1-3+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
