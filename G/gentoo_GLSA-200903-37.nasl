#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200903-37.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36003);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2009-0583", "CVE-2009-0584");
  script_bugtraq_id(34184);
  script_xref(name:"GLSA", value:"200903-37");

  script_name(english:"GLSA-200903-37 : Ghostscript: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200903-37
(Ghostscript: User-assisted execution of arbitrary code)

    Jan Lieskovsky from the Red Hat Security Response Team discovered the
    following vulnerabilities in Ghostscript's ICC Library:
    Multiple integer overflows (CVE-2009-0583).
    Multiple
    insufficient bounds checks on certain variable sizes
    (CVE-2009-0584).
  
Impact :

    A remote attacker could entice a user to open a specially crafted
    PostScript file containing images and a malicious ICC profile, possibly
    resulting in the execution of arbitrary code with the privileges of the
    user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200903-37"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GPL Ghostscript users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/ghostscript-gpl-8.64-r2'
    All GNU Ghostscript users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=app-text/ghostscript-gnu-8.62.0'
    We recommend that users unmerge ESP Ghostscript and use GPL or GNU
    Ghostscript instead:
    # emerge --unmerge 'app-text/ghostscript-esp'
    For installation instructions, see above."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ghostscript-esp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ghostscript-gnu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ghostscript-gpl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-text/ghostscript-esp", unaffected:make_list(), vulnerable:make_list("le 8.15.4-r1"))) flag++;
if (qpkg_check(package:"app-text/ghostscript-gpl", unaffected:make_list("ge 8.64-r2"), vulnerable:make_list("lt 8.64-r2"))) flag++;
if (qpkg_check(package:"app-text/ghostscript-gnu", unaffected:make_list("ge 8.62.0"), vulnerable:make_list("lt 8.62.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Ghostscript");
}
