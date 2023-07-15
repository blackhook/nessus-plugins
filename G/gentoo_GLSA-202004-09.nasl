#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202004-09.
#
# The advisory text is Copyright (C) 2001-2020 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(135427);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/16");

  script_cve_id("CVE-2020-6423", "CVE-2020-6430", "CVE-2020-6431", "CVE-2020-6432", "CVE-2020-6433", "CVE-2020-6434", "CVE-2020-6435", "CVE-2020-6436", "CVE-2020-6437", "CVE-2020-6438", "CVE-2020-6439", "CVE-2020-6440", "CVE-2020-6441", "CVE-2020-6442", "CVE-2020-6443", "CVE-2020-6444", "CVE-2020-6445", "CVE-2020-6446", "CVE-2020-6447", "CVE-2020-6448", "CVE-2020-6450", "CVE-2020-6451", "CVE-2020-6452", "CVE-2020-6454", "CVE-2020-6455", "CVE-2020-6456");
  script_xref(name:"GLSA", value:"202004-09");

  script_name(english:"GLSA-202004-09 : Chromium, Google Chrome: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202004-09
(Chromium, Google Chrome: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and Google
      Chrome. Please review the referenced CVE identifiers for details.
  
Impact :

    A remote attacker could entice a user to open a specially crafted HTML
      or multimedia file using Chromium or Google Chrome, possibly resulting in
      execution of arbitrary code with the privileges of the process or a
      Denial of Service condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202004-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-81.0.4044.92'
    All Google Chrome users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/google-chrome-81.0.4044.92'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 81.0.4044.92"), vulnerable:make_list("lt 81.0.4044.92"))) flag++;
if (qpkg_check(package:"www-client/google-chrome", unaffected:make_list("ge 81.0.4044.92"), vulnerable:make_list("lt 81.0.4044.92"))) flag++;

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
