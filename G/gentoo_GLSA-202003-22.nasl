#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202003-22.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(134599);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/27");

  script_cve_id("CVE-2019-8625", "CVE-2019-8674", "CVE-2019-8707", "CVE-2019-8710", "CVE-2019-8719", "CVE-2019-8720", "CVE-2019-8726", "CVE-2019-8733", "CVE-2019-8735", "CVE-2019-8743", "CVE-2019-8763", "CVE-2019-8764", "CVE-2019-8765", "CVE-2019-8766", "CVE-2019-8768", "CVE-2019-8769", "CVE-2019-8771", "CVE-2019-8782", "CVE-2019-8783", "CVE-2019-8808", "CVE-2019-8811", "CVE-2019-8812", "CVE-2019-8813", "CVE-2019-8814", "CVE-2019-8815", "CVE-2019-8816", "CVE-2019-8819", "CVE-2019-8820", "CVE-2019-8821", "CVE-2019-8822", "CVE-2019-8823", "CVE-2019-8835", "CVE-2019-8844", "CVE-2019-8846", "CVE-2020-3862", "CVE-2020-3864", "CVE-2020-3865", "CVE-2020-3867", "CVE-2020-3868");
  script_xref(name:"GLSA", value:"202003-22");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"GLSA-202003-22 : WebkitGTK+: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202003-22
(WebkitGTK+: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in WebKitGTK+. Please
      review the referenced CVE identifiers for details.
  
Impact :

    A remote attacker could execute arbitrary code, cause a Denial of
      Service condition, bypass intended memory-read restrictions, conduct a
      timing side-channel attack to bypass the Same Origin Policy or obtain
      sensitive information.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202003-22"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All WebkitGTK+ users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-libs/webkit-gtk-2.26.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3868");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webkit-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/16");
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

if (qpkg_check(package:"net-libs/webkit-gtk", unaffected:make_list("ge 2.26.4"), vulnerable:make_list("lt 2.26.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "WebkitGTK+");
}
