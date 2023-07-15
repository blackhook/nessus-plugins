#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200503-07.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17263);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-0543", "CVE-2005-0544", "CVE-2005-0653");
  script_xref(name:"GLSA", value:"200503-07");

  script_name(english:"GLSA-200503-07 : phpMyAdmin: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200503-07
(phpMyAdmin: Multiple vulnerabilities)

    phpMyAdmin contains several security issues:
    Maksymilian Arciemowicz has discovered multiple variable injection
    vulnerabilities that can be exploited through '$cfg' and 'GLOBALS'
    variables and localized strings
    It is possible to force phpMyAdmin to disclose information in error
    messages
    Failure to correctly escape special characters
  
Impact :

    By sending a specially crafted request, an attacker can include and
    execute arbitrary PHP code or cause path information disclosure.
    Furthermore the XSS issue allows an attacker to inject malicious script
    code, potentially compromising the victim's browser. Lastly the
    improper escaping of special characters results in unintended privilege
    settings for MySQL.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-1
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2005-1/"
  );
  # http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-2
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/PMASA-2005-2/"
  );
  # http://sourceforge.net/tracker/index.php?func=detail&aid=1113788&group_id=23067&atid=377408
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?502f7f16"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200503-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=dev-db/phpmyadmin-2.6.1_p2-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/04");
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

if (qpkg_check(package:"dev-db/phpmyadmin", unaffected:make_list("ge 2.6.1_p2-r1"), vulnerable:make_list("lt 2.6.1_p2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
