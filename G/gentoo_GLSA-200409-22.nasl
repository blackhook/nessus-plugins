#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-22.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14767);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-0875");
  script_xref(name:"GLSA", value:"200409-22");

  script_name(english:"GLSA-200409-22 : phpGroupWare: XSS vulnerability in wiki module");
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
"The remote host is affected by the vulnerability described in GLSA-200409-22
(phpGroupWare: XSS vulnerability in wiki module)

    Due to an input validation error, the wiki module in the phpGroupWare
    suite is vulnerable to cross site scripting attacks.
  
Impact :

    This vulnerability gives an attacker the ability to inject and execute
    malicious script code, potentially compromising the victim's browser.
  
Workaround :

    The is no known workaround at this time."
  );
  # http://downloads.phpgroupware.org/changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e38c06a"
  );
  # http://secunia.com/advisories/12466/
  script_set_attribute(
    attribute:"see_also",
    value:"https://secuniaresearch.flexerasoftware.com/advisories/12466/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All phpGroupWare users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=www-apps/phpgroupware-0.9.16.003'
    # emerge '>=www-apps/phpgroupware-0.9.16.003'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpgroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-apps/phpgroupware", unaffected:make_list("ge 0.9.16.003"), vulnerable:make_list("lt 0.9.16.003"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpGroupWare");
}
