#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202104-08.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149223);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2021-21142", "CVE-2021-21143", "CVE-2021-21144", "CVE-2021-21145", "CVE-2021-21146", "CVE-2021-21147", "CVE-2021-21148", "CVE-2021-21149", "CVE-2021-21150", "CVE-2021-21151", "CVE-2021-21152", "CVE-2021-21153", "CVE-2021-21154", "CVE-2021-21155", "CVE-2021-21156", "CVE-2021-21157", "CVE-2021-21159", "CVE-2021-21160", "CVE-2021-21161", "CVE-2021-21162", "CVE-2021-21163", "CVE-2021-21165", "CVE-2021-21166", "CVE-2021-21167", "CVE-2021-21168", "CVE-2021-21169", "CVE-2021-21170", "CVE-2021-21171", "CVE-2021-21172", "CVE-2021-21173", "CVE-2021-21174", "CVE-2021-21175", "CVE-2021-21176", "CVE-2021-21177", "CVE-2021-21178", "CVE-2021-21179", "CVE-2021-21180", "CVE-2021-21181", "CVE-2021-21182", "CVE-2021-21183", "CVE-2021-21184", "CVE-2021-21185", "CVE-2021-21186", "CVE-2021-21187", "CVE-2021-21188", "CVE-2021-21189", "CVE-2021-2119", "CVE-2021-21191", "CVE-2021-21192", "CVE-2021-21193", "CVE-2021-21194", "CVE-2021-21195", "CVE-2021-21196", "CVE-2021-21197", "CVE-2021-21198", "CVE-2021-21199", "CVE-2021-21201", "CVE-2021-21202", "CVE-2021-21203", "CVE-2021-21204", "CVE-2021-21205", "CVE-2021-21206", "CVE-2021-21207", "CVE-2021-21208", "CVE-2021-21209", "CVE-2021-21210", "CVE-2021-21211", "CVE-2021-21212", "CVE-2021-21213", "CVE-2021-21214", "CVE-2021-21215", "CVE-2021-21216", "CVE-2021-21217", "CVE-2021-21218", "CVE-2021-21219", "CVE-2021-21220", "CVE-2021-21221", "CVE-2021-21222", "CVE-2021-21223", "CVE-2021-21224", "CVE-2021-21225", "CVE-2021-21226", "CVE-2021-21227", "CVE-2021-21228", "CVE-2021-21229", "CVE-2021-21230", "CVE-2021-21231", "CVE-2021-21232", "CVE-2021-21233");
  script_xref(name:"GLSA", value:"202104-08");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0007");

  script_name(english:"GLSA-202104-08 : Chromium, Google Chrome: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202104-08
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
    value:"https://security.gentoo.org/glsa/202104-08"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-90.0.4430.93'
    All Google Chrome users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/google-chrome-90.0.4430.93'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21233");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome versions before 89.0.4389.128 V8 XOR Typer Out-Of-Bounds Access RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 90.0.4430.93"), vulnerable:make_list("lt 90.0.4430.93"))) flag++;
if (qpkg_check(package:"www-client/google-chrome", unaffected:make_list("ge 90.0.4430.93"), vulnerable:make_list("lt 90.0.4430.93"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / Google Chrome");
}
