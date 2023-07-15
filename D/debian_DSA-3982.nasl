#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3982. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103392);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-12837", "CVE-2017-12883");
  script_xref(name:"DSA", value:"3982");

  script_name(english:"Debian DSA-3982-1 : perl - security update");
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

  - CVE-2017-12837
    Jakub Wilk reported a heap buffer overflow flaw in the
    regular expression compiler, allowing a remote attacker
    to cause a denial of service via a specially crafted
    regular expression with the case-insensitive modifier.

  - CVE-2017-12883
    Jakub Wilk reported a buffer over-read flaw in the
    regular expression parser, allowing a remote attacker to
    cause a denial of service or information leak."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=875596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=875597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-12883"
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
    value:"https://www.debian.org/security/2017/dsa-3982"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 5.20.2-3+deb8u9.

For the stable distribution (stretch), these problems have been fixed
in version 5.24.1-3+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/22");
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
if (deb_check(release:"8.0", prefix:"libperl-dev", reference:"5.20.2-3+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libperl5.20", reference:"5.20.2-3+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"perl", reference:"5.20.2-3+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"perl-base", reference:"5.20.2-3+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"perl-debug", reference:"5.20.2-3+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"perl-doc", reference:"5.20.2-3+deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"perl-modules", reference:"5.20.2-3+deb8u9")) flag++;
if (deb_check(release:"9.0", prefix:"libperl-dev", reference:"5.24.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libperl5.24", reference:"5.24.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"perl", reference:"5.24.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"perl-base", reference:"5.24.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"perl-debug", reference:"5.24.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"perl-doc", reference:"5.24.1-3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"perl-modules-5.24", reference:"5.24.1-3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
