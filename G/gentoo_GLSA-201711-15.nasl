#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201711-15.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104696);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-9841");
  script_xref(name:"GLSA", value:"201711-15");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0665");

  script_name(english:"GLSA-201711-15 : PHPUnit: Remote code execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote Gentoo host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-201711-15
(PHPUnit: Remote code execution)

    When PHPUnit is installed in a production environment via composer and
      these modules are in a web accessible directory, the eval-stdin.php file
      in PHPUnit contains vulnerable statements that trigger the vulnerability.
  
Impact :

    A remote attacker could possibly execute arbitrary PHP code or cause a
      Denial of Service condition.
  
Workaround :

    There are several ways to fix or mitigate this vulnerability:
    Remove PHPUnit from the production environment.
    Update PHPUnit.
    Manually apply the patch.
    Disable direct access to the composer packages by placing .htaccess file
      to /vendor folder.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/201711-15");
  script_set_attribute(attribute:"solution", value:
"All PHPUnit users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-php/phpunit-5.7.15-r1'");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:phpunit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

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

if (qpkg_check(package:"dev-php/phpunit", unaffected:make_list("ge 5.7.15-r1"), vulnerable:make_list("lt 5.7.15-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PHPUnit");
}
