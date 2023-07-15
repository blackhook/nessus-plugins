#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201909-05.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(128594);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2019-11070", "CVE-2019-6201", "CVE-2019-6251", "CVE-2019-7285", "CVE-2019-7292", "CVE-2019-8503", "CVE-2019-8506", "CVE-2019-8515", "CVE-2019-8518", "CVE-2019-8523", "CVE-2019-8524", "CVE-2019-8535", "CVE-2019-8536", "CVE-2019-8544", "CVE-2019-8551", "CVE-2019-8558", "CVE-2019-8559", "CVE-2019-8563", "CVE-2019-8595", "CVE-2019-8607", "CVE-2019-8615", "CVE-2019-8644", "CVE-2019-8649", "CVE-2019-8658", "CVE-2019-8666", "CVE-2019-8669", "CVE-2019-8671", "CVE-2019-8672", "CVE-2019-8673", "CVE-2019-8676", "CVE-2019-8677", "CVE-2019-8678", "CVE-2019-8679", "CVE-2019-8680", "CVE-2019-8681", "CVE-2019-8683", "CVE-2019-8684", "CVE-2019-8686", "CVE-2019-8687", "CVE-2019-8688", "CVE-2019-8689", "CVE-2019-8690");
  script_xref(name:"GLSA", value:"201909-05");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"GLSA-201909-05 : WebkitGTK+: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201909-05
(WebkitGTK+: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in WebkitGTK+. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    An attacker, by enticing a user to visit maliciously crafted web
      content, may be able to execute arbitrary code or cause memory
      corruption.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://webkitgtk.org/security/WSA-2019-0002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://webkitgtk.org/security/WSA-2019-0004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201909-05"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All WebkitGTK+ users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-libs/webkit-gtk-2.24.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8689");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webkit-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"net-libs/webkit-gtk", unaffected:make_list("ge 2.24.4"), vulnerable:make_list("lt 2.24.4"))) flag++;

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
