#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-978-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100624);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-6512");

  script_name(english:"Debian DLA-978-1 : perl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The cPanel Security Team reported a time of check to time of use
(TOCTTOU) race condition flaw in File::Path, a core module from Perl
to create or remove directory trees. An attacker can take advantage of
this flaw to set the mode on an attacker-chosen file to an
attacker-chosen value.

For Debian 7 'Wheezy', these problems have been fixed in version
5.14.2-21+deb7u5.

We recommend that you upgrade your perl packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/06/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/perl"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcgi-fast-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libperl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libperl5.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libcgi-fast-perl", reference:"5.14.2-21+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libperl-dev", reference:"5.14.2-21+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libperl5.14", reference:"5.14.2-21+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"perl", reference:"5.14.2-21+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"perl-base", reference:"5.14.2-21+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"perl-debug", reference:"5.14.2-21+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"perl-doc", reference:"5.14.2-21+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"perl-modules", reference:"5.14.2-21+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");