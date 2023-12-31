#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-11340.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48324);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2010-1168", "CVE-2010-1447");
  script_bugtraq_id(40302, 40305);
  script_xref(name:"FEDORA", value:"2010-11340");

  script_name(english:"Fedora 12 : perl-5.10.0-91.fc12 (2010-11340)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Wed Jul 21 2010 Marcela Maslaova <mmaslano at
    redhat.com> - 4:5.10.0-91

    - CVE-2010-1168 perl Safe: Intended restriction bypass
      via object references

    - CVE-2010-1447 perl: Safe restriction bypass when
      reference to subroutine in compartment is called from
      outside

  - 576824 RT#73814 - unpack() didn't handle scalar context
    correctly

    - Resolves: rhbz#588269, rhbz#576508

    - Fri Jul 9 2010 Petr Pisar <ppisar at redhat.com> -
      4:5.10.0-90

    - Add Digest::SHA requirement to perl-CPAN and
      perl-CPANPLUS (bug #612563)

    - Wed Jul 7 2010 Petr Pisar <ppisar at redhat.com> -
      4:5.10.0-89

    - Fix perl-5.10.0-Encode-err.patch patch to be
      applicable

    - Fix incorrect return code on failed extraction by
      upgrading Archive::Tar to 1.62 (bug #607687)

  - Wed Mar 17 2010 Marcela Maslaova <mmaslano at
    redhat.com> - 4:5.10.0-88

    - rebuild, e.g. Patch62 is missing in koji build

    - Tue Dec 1 2009 Stepan Kasal <skasal at redhat.com> -
      4:5.10.0-87

    - fix patch-update-Compress-Raw-Zlib.patch (did not
      patch Zlib.pm)

    - update Compress::Raw::Zlib to 2.023

    - update IO::Compress::Base, and IO::Compress::Zlib to
      2.015 (#542645)

    - Mon Nov 30 2009 Marcela Maslaova <mmaslano at
      redhat.com> - 4:5.10.0-86

    - 542645 update IO-Compress-Base

    - Tue Nov 24 2009 Stepan Kasal <skasal at redhat.com> -
      4:5.10.0-85

    - back out perl-5.10.0-spamassassin.patch (#528572)

    - Thu Oct 1 2009 Chris Weyl <cweyl at alumni.drew.edu> -
      4:5.10.0-84

    - add /perl(UNIVERSAL)/d; /perl(DB)/d to
      perl_default_filter auto-provides filtering

  - Thu Oct 1 2009 Stepan Kasal <skasal at redhat.com> -
    4:5.10.0-83

    - update Storable to 2.21

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=576508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=588269"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-August/045418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a1b13b6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"perl-5.10.0-91.fc12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}
