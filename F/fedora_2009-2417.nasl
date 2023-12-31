#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-2417.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38079);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2008-4437", "CVE-2008-6098", "CVE-2009-0481", "CVE-2009-0482", "CVE-2009-0483", "CVE-2009-0484", "CVE-2009-0485", "CVE-2009-0486");
  script_bugtraq_id(30661, 32178);
  script_xref(name:"FEDORA", value:"2009-2417");

  script_name(english:"Fedora 10 : bugzilla-3.2.2-2.fc10 (2009-2417)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Mar 5 2009 Itamar Reis Peixoto <itamar at
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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=465956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=484755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=484805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=484806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=484807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=484811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=484812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=484813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021480.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d913629"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bugzilla package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 264, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/05");
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
if (rpm_check(release:"FC10", reference:"bugzilla-3.2.2-2.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bugzilla");
}
