#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4347. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119290);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/19");

  script_cve_id("CVE-2018-18311", "CVE-2018-18312", "CVE-2018-18313", "CVE-2018-18314");
  script_xref(name:"DSA", value:"4347");
  script_xref(name:"IAVA", value:"2018-A-0407-S");

  script_name(english:"Debian DSA-4347-1 : perl - security update");
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

  - CVE-2018-18311
    Jayakrishna Menon and Christophe Hauser discovered an
    integer overflow vulnerability in Perl_my_setenv leading
    to a heap-based buffer overflow with attacker-controlled
    input.

  - CVE-2018-18312
    Eiichi Tsukata discovered that a crafted regular
    expression could cause a heap-based buffer overflow
    write during compilation, potentially allowing arbitrary
    code execution.

  - CVE-2018-18313
    Eiichi Tsukata discovered that a crafted regular
    expression could cause a heap-based buffer overflow read
    during compilation which leads to information leak.

  - CVE-2018-18314
    Jakub Wilk discovered that a specially crafted regular
    expression could lead to a heap-based buffer overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-18314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4347"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the perl packages.

For the stable distribution (stretch), these problems have been fixed
in version 5.24.1-3+deb9u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libperl-dev", reference:"5.24.1-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"libperl5.24", reference:"5.24.1-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"perl", reference:"5.24.1-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"perl-base", reference:"5.24.1-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"perl-debug", reference:"5.24.1-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"perl-doc", reference:"5.24.1-3+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"perl-modules-5.24", reference:"5.24.1-3+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
