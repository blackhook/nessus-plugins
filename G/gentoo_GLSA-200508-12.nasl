#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200508-12.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19485);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-2549", "CVE-2005-2550");
  script_xref(name:"GLSA", value:"200508-12");

  script_name(english:"GLSA-200508-12 : Evolution: Format string vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200508-12
(Evolution: Format string vulnerabilities)

    Ulf Harnhammar discovered that Evolution is vulnerable to format
    string bugs when viewing attached vCards and when displaying contact
    information from remote LDAP servers or task list data from remote
    servers (CAN-2005-2549). He also discovered that Evolution fails to
    handle special calendar entries if the user switches to the Calendars
    tab (CAN-2005-2550).
  
Impact :

    An attacker could attach specially crafted vCards to emails or
    setup malicious LDAP servers or calendar entries which would trigger
    the format string vulnerabilities when viewed or accessed from
    Evolution. This could potentially result in the execution of arbitrary
    code with the rights of the user running Evolution.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.sitic.se/eng/advisories_and_recommendations/sa05-001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200508-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Evolution users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/evolution-2.2.3-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:evolution");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/10");
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

if (qpkg_check(package:"mail-client/evolution", unaffected:make_list("ge 2.2.3-r3"), vulnerable:make_list("lt 2.2.3-r3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Evolution");
}
