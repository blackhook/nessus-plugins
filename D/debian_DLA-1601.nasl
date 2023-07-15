#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1601-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119311);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-18311");
  script_xref(name:"IAVA", value:"2018-A-0407-S");

  script_name(english:"Debian DLA-1601-1 : perl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Jayakrishna Menon and Christophe Hauser discovered an integer overflow
vulnerability in Perl_my_setenv leading to a heap-based buffer
overflow with attacker-controlled input.

For Debian 8 'Jessie', this problem has been fixed in version
5.20.2-3+deb8u12.

We recommend that you upgrade your perl packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/perl"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libperl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libperl5.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perl-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"libperl-dev", reference:"5.20.2-3+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libperl5.20", reference:"5.20.2-3+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"perl", reference:"5.20.2-3+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"perl-base", reference:"5.20.2-3+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"perl-debug", reference:"5.20.2-3+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"perl-doc", reference:"5.20.2-3+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"perl-modules", reference:"5.20.2-3+deb8u12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
