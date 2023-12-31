#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-3410.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37599);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2009-1213");
  script_bugtraq_id(34308);
  script_xref(name:"FEDORA", value:"2009-3410");

  script_name(english:"Fedora 10 : bugzilla-3.2.3-1.fc10 (2009-3410)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Apr 6 2009 Itamar Reis Peixoto <itamar at
    ispbrasil.com.br> 3.2.3-1

    - fix CVE-2009-1213

    - Thu Mar 5 2009 Itamar Reis Peixoto <itamar at
      ispbrasil.com.br> 3.2.2-2

    - fix from BZ #474250 Comment #16, from Chris Eveleigh
      -->

    - add python BR for contrib subpackage

    - fix description

    - change Requires perl-SOAP-Lite to perl(SOAP::Lite)
      according guidelines

    - Sun Mar 1 2009 Itamar Reis Peixoto <itamar at
      ispbrasil.com.br> 3.2.2-1

    - thanks to Chris Eveleigh <chris dot eveleigh at
      planningportal dot gov dot uk>

    - for contributing with patches :-)

    - Upgrade to upstream 3.2.2 to fix multiple security
      vulns

    - Removed old perl_requires exclusions, added new ones
      for RADIUS, Oracle and sanitycheck.cgi

    - Added Oracle to supported DBs in description (and
      moved line breaks)

    - Include a patch to fix max_allowed_packet warnin when
      using with mysql

    - Sat Feb 28 2009 Itamar Reis Peixoto <itamar at
      ispbrasil.com.br> 3.0.8-1

    - Upgrade to 3.0.8, fix #466077 #438080

    - fix macro in changelog rpmlint warning

    - fix files-attr-not-set rpmlint warning for doc and
      contrib sub-packages

    - Mon Feb 23 2009 Fedora Release Engineering <rel-eng at
      lists.fedoraproject.org> - 3.0.4-4

    - Rebuilt for
      https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    - Mon Feb 2 2009 Stepan Kasal <skasal at redhat.com> -
      3.0.4-3

    - do not require perl-Email-Simple, it is (no longer) in
      use

    - remove several explicit perl-* requires; the automatic
      dependencies do handle them

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=494398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022137.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?700bf45f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bugzilla package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"bugzilla-3.2.3-1.fc10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bugzilla");
}
