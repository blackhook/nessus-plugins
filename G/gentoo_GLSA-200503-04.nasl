#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200503-04.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17251);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-0565", "CVE-2005-0572");
  script_xref(name:"GLSA", value:"200503-04");

  script_name(english:"GLSA-200503-04 : phpWebSite: Arbitrary PHP execution and path disclosure");
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
"The remote host is affected by the vulnerability described in GLSA-200503-04
(phpWebSite: Arbitrary PHP execution and path disclosure)

    NST discovered that, when submitting an announcement, uploaded files
    aren't correctly checked for malicious code. They also found out that
    phpWebSite is vulnerable to a path disclosure.
  
Impact :

    A remote attacker can exploit this issue to upload files to a directory
    within the web root. By calling the uploaded script the attacker could
    then execute arbitrary PHP code with the rights of the web server. By
    passing specially crafted requests to the search module, remote
    attackers can also find out the full path of PHP scripts.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://secunia.com/advisories/14399/
  script_set_attribute(
    attribute:"see_also",
    value:"https://secuniaresearch.flexerasoftware.com/advisories/14399/"
  );
  # http://phpwebsite.appstate.edu/index.php?module=announce&ANN_id=922&ANN_user_op=view
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13948819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200503-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All phpWebSite users should upgrade to the latest available version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/phpwebsite-0.10.0-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpwebsite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-apps/phpwebsite", unaffected:make_list("ge 0.10.0-r2"), vulnerable:make_list("lt 0.10.0-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpWebSite");
}
