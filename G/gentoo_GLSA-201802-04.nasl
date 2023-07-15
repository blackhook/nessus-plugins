#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201802-04.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(106885);
  script_version("3.3");
  script_cvs_date("Date: 2019/04/05 23:25:06");

  script_cve_id("CVE-2017-10155", "CVE-2017-10227", "CVE-2017-10268", "CVE-2017-10276", "CVE-2017-10283", "CVE-2017-10286", "CVE-2017-10294", "CVE-2017-10314", "CVE-2017-10378", "CVE-2017-10379", "CVE-2017-10384", "CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3329", "CVE-2017-3450", "CVE-2017-3452", "CVE-2017-3453", "CVE-2017-3456", "CVE-2017-3461", "CVE-2017-3462", "CVE-2017-3463", "CVE-2017-3464", "CVE-2017-3599", "CVE-2017-3600", "CVE-2017-3633", "CVE-2017-3634", "CVE-2017-3635", "CVE-2017-3636", "CVE-2017-3637", "CVE-2017-3641", "CVE-2017-3647", "CVE-2017-3648", "CVE-2017-3649", "CVE-2017-3651", "CVE-2017-3652", "CVE-2017-3653", "CVE-2017-3732", "CVE-2018-2562", "CVE-2018-2573", "CVE-2018-2583", "CVE-2018-2590", "CVE-2018-2591", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2645", "CVE-2018-2647", "CVE-2018-2665", "CVE-2018-2668", "CVE-2018-2696", "CVE-2018-2703");
  script_xref(name:"GLSA", value:"201802-04");

  script_name(english:"GLSA-201802-04 : MySQL: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201802-04
(MySQL: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MySQL. Please review
      the referenced CVE identifiers for details.
  
Impact :

    A remote attacker could execute arbitrary code without authentication or
      cause a partial denial of service condition.
  
Workaround :

    There are no known workarounds at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201802-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MySQL users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-db/mysql-5.6.39'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"dev-db/mysql", unaffected:make_list("ge 5.6.39"), vulnerable:make_list("lt 5.6.39"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MySQL");
}
