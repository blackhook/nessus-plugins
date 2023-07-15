#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202012-05.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(143495);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-16014", "CVE-2020-16015", "CVE-2020-16018", "CVE-2020-16019", "CVE-2020-16020", "CVE-2020-16021", "CVE-2020-16022", "CVE-2020-16023", "CVE-2020-16024", "CVE-2020-16025", "CVE-2020-16026", "CVE-2020-16027", "CVE-2020-16028", "CVE-2020-16029", "CVE-2020-16030", "CVE-2020-16031", "CVE-2020-16032", "CVE-2020-16033", "CVE-2020-16034", "CVE-2020-16036", "CVE-2020-16037", "CVE-2020-16038", "CVE-2020-16039", "CVE-2020-16040", "CVE-2020-16041", "CVE-2020-16042");
  script_xref(name:"GLSA", value:"202012-05");
  script_xref(name:"IAVA", value:"2020-A-0533-S");
  script_xref(name:"IAVA", value:"2020-A-0571-S");

  script_name(english:"GLSA-202012-05 : Chromium, Google Chrome: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202012-05
(Chromium, Google Chrome: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and Google
      Chrome. Please review the CVE identifiers referenced below for details.
  
Impact :

    Please review the referenced CVE identifiers for details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202012-05"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-87.0.4280.88'
    All Google Chrome users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/google-chrome-87.0.4280.88'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16039");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome versions before 87.0.4280.88 integer overflow during SimplfiedLowering phase');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 87.0.4280.88"), vulnerable:make_list("lt 87.0.4280.88"))) flag++;
if (qpkg_check(package:"www-client/google-chrome", unaffected:make_list("ge 87.0.4280.88"), vulnerable:make_list("lt 87.0.4280.88"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / Google Chrome");
}
