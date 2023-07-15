#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202003-02.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(134469);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2019-11745", "CVE-2019-17005", "CVE-2019-17008", "CVE-2019-17010", "CVE-2019-17011", "CVE-2019-17012", "CVE-2019-17016", "CVE-2019-17017", "CVE-2019-17022", "CVE-2019-17024", "CVE-2019-17026", "CVE-2019-20503", "CVE-2020-6796", "CVE-2020-6797", "CVE-2020-6798", "CVE-2020-6799", "CVE-2020-6800", "CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6811", "CVE-2020-6812", "CVE-2020-6814");
  script_xref(name:"GLSA", value:"202003-02");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0007");

  script_name(english:"GLSA-202003-02 : Mozilla Firefox: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202003-02
(Mozilla Firefox: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Mozilla Firefox. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user to view a specially crafted web
      page, possibly resulting in the execution of arbitrary code with the
      privileges of the process or a Denial of Service condition. Furthermore,
      a remote attacker may be able to perform Man-in-the-Middle attacks,
      obtain sensitive information, spoof the address bar, conduct clickjacking
      attacks, bypass security restrictions and protection mechanisms, or have
      other unspecified impact.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-37/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-03/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-06/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-09/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202003-02"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Mozilla Firefox users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-68.6.0'
    All Mozilla Firefox binary users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=www-client/firefox-bin-68.6.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6814");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:firefox-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if (qpkg_check(package:"www-client/firefox", unaffected:make_list("ge 68.6.0"), vulnerable:make_list("lt 68.6.0"))) flag++;
if (qpkg_check(package:"www-client/firefox-bin", unaffected:make_list("ge 68.6.0"), vulnerable:make_list("lt 68.6.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox");
}
