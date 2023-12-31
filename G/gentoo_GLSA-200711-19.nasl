#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200711-19.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(28219);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-5423", "CVE-2007-5682");
  script_xref(name:"GLSA", value:"200711-19");

  script_name(english:"GLSA-200711-19 : TikiWiki: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200711-19
(TikiWiki: Multiple vulnerabilities)

    Stefan Esser reported that a previous vulnerability (CVE-2007-5423,
    GLSA 200710-21) was not properly fixed in TikiWiki 1.9.8.1
    (CVE-2007-5682). The TikiWiki development team also added several
    checks to avoid file inclusion.
  
Impact :

    A remote attacker could exploit these vulnerabilities to inject
    arbitrary code with the privileges of the user running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200710-21"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200711-19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All TikiWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/tikiwiki-1.9.8.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TikiWiki tiki-graph_formula Remote PHP Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tikiwiki");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-apps/tikiwiki", unaffected:make_list("ge 1.9.8.3"), vulnerable:make_list("lt 1.9.8.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "TikiWiki");
}
