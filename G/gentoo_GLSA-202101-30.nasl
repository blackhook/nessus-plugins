#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202101-30.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(145430);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-15959", "CVE-2020-15960", "CVE-2020-15961", "CVE-2020-15962", "CVE-2020-15963", "CVE-2020-15964", "CVE-2020-15965", "CVE-2020-15966", "CVE-2020-15968", "CVE-2020-15969", "CVE-2020-15972", "CVE-2020-15974", "CVE-2020-15976", "CVE-2020-15977", "CVE-2020-15978", "CVE-2020-15979", "CVE-2020-15985", "CVE-2020-15987", "CVE-2020-15989", "CVE-2020-15992", "CVE-2020-16001", "CVE-2020-16002", "CVE-2020-16003", "CVE-2020-6467", "CVE-2020-6470", "CVE-2020-6471", "CVE-2020-6472", "CVE-2020-6473", "CVE-2020-6474", "CVE-2020-6475", "CVE-2020-6476", "CVE-2020-6480", "CVE-2020-6481", "CVE-2020-6482", "CVE-2020-6483", "CVE-2020-6486", "CVE-2020-6487", "CVE-2020-6489", "CVE-2020-6490", "CVE-2020-6506", "CVE-2020-6510", "CVE-2020-6511", "CVE-2020-6512", "CVE-2020-6513", "CVE-2020-6514", "CVE-2020-6518", "CVE-2020-6523", "CVE-2020-6524", "CVE-2020-6526", "CVE-2020-6529", "CVE-2020-6530", "CVE-2020-6531", "CVE-2020-6532", "CVE-2020-6533", "CVE-2020-6534", "CVE-2020-6535", "CVE-2020-6540", "CVE-2020-6541", "CVE-2020-6542", "CVE-2020-6543", "CVE-2020-6544", "CVE-2020-6545", "CVE-2020-6548", "CVE-2020-6549", "CVE-2020-6550", "CVE-2020-6551", "CVE-2020-6555", "CVE-2020-6557", "CVE-2020-6559", "CVE-2020-6561", "CVE-2020-6562", "CVE-2020-6569", "CVE-2020-6570", "CVE-2020-6571", "CVE-2020-6573", "CVE-2020-6575", "CVE-2020-6576");
  script_xref(name:"GLSA", value:"202101-30");

  script_name(english:"GLSA-202101-30 : Qt WebEngine: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202101-30
(Qt WebEngine: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Qt WebEngine. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    Please review the referenced CVE identifiers for details.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202101-30"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Qt WebEngine users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-qt/qtwebengine-5.15.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6559");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:qtwebengine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/26");
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

if (qpkg_check(package:"dev-qt/qtwebengine", unaffected:make_list("ge 5.15.2"), vulnerable:make_list("lt 5.15.2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Qt WebEngine");
}
