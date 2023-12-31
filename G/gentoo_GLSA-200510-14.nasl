#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200510-14.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20034);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-4278", "CVE-2005-4279", "CVE-2005-4280");
  script_xref(name:"GLSA", value:"200510-14");

  script_name(english:"GLSA-200510-14 : Perl, Qt-UnixODBC, CMake: RUNPATH issues");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200510-14
(Perl, Qt-UnixODBC, CMake: RUNPATH issues)

    Some packages may introduce insecure paths into the list of directories
    that are searched for libraries at runtime. Furthermore, packages
    depending on the MakeMaker Perl module for build configuration may have
    incorrectly copied the LD_RUN_PATH into the DT_RPATH.
  
Impact :

    A local attacker, who is a member of the 'portage' group, could create
    a malicious shared object in the Portage temporary build directory that
    would be loaded at runtime by a dependent executable, potentially
    resulting in privilege escalation.
  
Workaround :

    Only grant 'portage' group rights to trusted users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200510-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Perl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-lang/perl
    All Qt-UnixODBC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-db/qt-unixODBC-3.3.4-r1'
    All CMake users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-util/cmake"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cmake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qt-unixODBC");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"dev-util/cmake", unaffected:make_list("ge 2.2.0-r1", "rge 2.0.6-r1"), vulnerable:make_list("lt 2.2.0-r1"))) flag++;
if (qpkg_check(package:"dev-db/qt-unixODBC", unaffected:make_list("ge 3.3.4-r1"), vulnerable:make_list("lt 3.3.4-r1"))) flag++;
if (qpkg_check(package:"dev-lang/perl", unaffected:make_list("ge 5.8.7-r1", "rge 5.8.6-r6"), vulnerable:make_list("lt 5.8.7-r1"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Perl / Qt-UnixODBC / CMake");
}
