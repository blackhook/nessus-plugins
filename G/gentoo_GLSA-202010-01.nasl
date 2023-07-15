#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202010-01.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(141505);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/13");

  script_cve_id(
    "CVE-2020-15967",
    "CVE-2020-15968",
    "CVE-2020-15969",
    "CVE-2020-15970",
    "CVE-2020-15971",
    "CVE-2020-15972",
    "CVE-2020-15973",
    "CVE-2020-15974",
    "CVE-2020-15975",
    "CVE-2020-15976",
    "CVE-2020-15977",
    "CVE-2020-15978",
    "CVE-2020-15979",
    "CVE-2020-15980",
    "CVE-2020-15981",
    "CVE-2020-15982",
    "CVE-2020-15983",
    "CVE-2020-15984",
    "CVE-2020-15985",
    "CVE-2020-15986",
    "CVE-2020-15987",
    "CVE-2020-15988",
    "CVE-2020-15989",
    "CVE-2020-15990",
    "CVE-2020-15991",
    "CVE-2020-15992",
    "CVE-2020-6557"
  );
  script_xref(name:"GLSA", value:"202010-01");
  script_xref(name:"IAVA", value:"2020-A-0472-S");

  script_name(english:"GLSA-202010-01 : Chromium, Google Chrome: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202010-01
(Chromium, Google Chrome: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and Google
      Chrome. Please review the CVE identifiers referenced below for details.
  
Impact :

    Please review the referenced CVE identifiers for details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202010-01");
  script_set_attribute(
    attribute:"solution",
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-86.0.4240.75'
    All Google Chrome users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/google-chrome-86.0.4240.75'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15992");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 86.0.4240.75"), vulnerable:make_list("lt 86.0.4240.75"))) flag++;
if (qpkg_check(package:"www-client/google-chrome", unaffected:make_list("ge 86.0.4240.75"), vulnerable:make_list("lt 86.0.4240.75"))) flag++;

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
