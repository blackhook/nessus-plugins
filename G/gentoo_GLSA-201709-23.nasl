#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201709-23.
#
# The advisory text is Copyright (C) 2001-2018 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103462);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-11108", "CVE-2017-11541", "CVE-2017-11542", "CVE-2017-11543", "CVE-2017-11544", "CVE-2017-12893", "CVE-2017-12894", "CVE-2017-12895", "CVE-2017-12896", "CVE-2017-12897", "CVE-2017-12898", "CVE-2017-12899", "CVE-2017-12900", "CVE-2017-12901", "CVE-2017-12902", "CVE-2017-12985", "CVE-2017-12986", "CVE-2017-12987", "CVE-2017-12988", "CVE-2017-12989", "CVE-2017-12990", "CVE-2017-12991", "CVE-2017-12992", "CVE-2017-12993", "CVE-2017-12994", "CVE-2017-12995", "CVE-2017-12996", "CVE-2017-12997", "CVE-2017-12998", "CVE-2017-12999", "CVE-2017-13000", "CVE-2017-13001", "CVE-2017-13002", "CVE-2017-13003", "CVE-2017-13004", "CVE-2017-13005", "CVE-2017-13006", "CVE-2017-13007", "CVE-2017-13008", "CVE-2017-13009", "CVE-2017-13010", "CVE-2017-13011", "CVE-2017-13012", "CVE-2017-13013", "CVE-2017-13014", "CVE-2017-13015", "CVE-2017-13016", "CVE-2017-13017", "CVE-2017-13018", "CVE-2017-13019", "CVE-2017-13020", "CVE-2017-13021", "CVE-2017-13022", "CVE-2017-13023", "CVE-2017-13024", "CVE-2017-13025", "CVE-2017-13026", "CVE-2017-13027", "CVE-2017-13028", "CVE-2017-13029", "CVE-2017-13030", "CVE-2017-13031", "CVE-2017-13032", "CVE-2017-13033", "CVE-2017-13034", "CVE-2017-13035", "CVE-2017-13036", "CVE-2017-13037", "CVE-2017-13038", "CVE-2017-13039", "CVE-2017-13040", "CVE-2017-13041", "CVE-2017-13042", "CVE-2017-13043", "CVE-2017-13044", "CVE-2017-13045", "CVE-2017-13046", "CVE-2017-13047", "CVE-2017-13048", "CVE-2017-13049", "CVE-2017-13050", "CVE-2017-13051", "CVE-2017-13052", "CVE-2017-13053", "CVE-2017-13054", "CVE-2017-13055", "CVE-2017-13687", "CVE-2017-13688", "CVE-2017-13689", "CVE-2017-13690", "CVE-2017-13725");
  script_xref(name:"GLSA", value:"201709-23");

  script_name(english:"GLSA-201709-23 : Tcpdump: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201709-23
(Tcpdump: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Tcpdump. Please review
      the referenced CVE identifiers for details.
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the process or cause a Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201709-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Tcpdump users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-analyzer/tcpdump-4.9.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-analyzer/tcpdump", unaffected:make_list("ge 4.9.2"), vulnerable:make_list("lt 4.9.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Tcpdump");
}
