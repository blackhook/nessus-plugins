#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200405-12.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14498);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-0396");
  script_xref(name:"GLSA", value:"200405-12");

  script_name(english:"GLSA-200405-12 : CVS heap overflow vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200405-12
(CVS heap overflow vulnerability)

    Stefan Esser discovered a heap overflow in the CVS server, which can be
    triggered by sending malicious 'Entry' lines and manipulating the flags
    related to that Entry. This vulnerability was proven to be exploitable.
  
Impact :

    A remote attacker can execute arbitrary code on the CVS server, with the
    rights of the CVS server. By default, Gentoo uses the 'cvs' user to run the
    CVS server. In particular, this flaw allows a complete compromise of CVS
    source repositories. If you're not running a server, then you are not
    vulnerable.
  
Workaround :

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of CVS."
  );
  # http://security.e-matters.de/advisories/072004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://archive.cert.uni-stuttgart.de/bugtraq/2004/05/msg00219.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200405-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users running a CVS server should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=dev-util/cvs-1.11.16'
    # emerge '>=dev-util/cvs-1.11.16'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cvs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-util/cvs", unaffected:make_list("ge 1.11.16"), vulnerable:make_list("le 1.11.15"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dev-util/cvs");
}
