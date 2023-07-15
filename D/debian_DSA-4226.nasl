#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4226. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110464);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/19");

  script_cve_id("CVE-2018-12015");
  script_xref(name:"DSA", value:"4226");
  script_xref(name:"IAVA", value:"2018-A-0407-S");

  script_name(english:"Debian DSA-4226-1 : perl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jakub Wilk discovered a directory traversal flaw in the Archive::Tar
module, allowing an attacker to overwrite any file writable by the
extracting user via a specially crafted tar archive."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=900834"
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
    value:"https://www.debian.org/security/2018/dsa-4226"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the perl packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 5.20.2-3+deb8u11.

For the stable distribution (stretch), this problem has been fixed in
version 5.24.1-3+deb9u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");
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
if (deb_check(release:"8.0", prefix:"libperl-dev", reference:"5.20.2-3+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libperl5.20", reference:"5.20.2-3+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"perl", reference:"5.20.2-3+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"perl-base", reference:"5.20.2-3+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"perl-debug", reference:"5.20.2-3+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"perl-doc", reference:"5.20.2-3+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"perl-modules", reference:"5.20.2-3+deb8u11")) flag++;
if (deb_check(release:"9.0", prefix:"libperl-dev", reference:"5.24.1-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libperl5.24", reference:"5.24.1-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"perl", reference:"5.24.1-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"perl-base", reference:"5.24.1-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"perl-debug", reference:"5.24.1-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"perl-doc", reference:"5.24.1-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"perl-modules-5.24", reference:"5.24.1-3+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
