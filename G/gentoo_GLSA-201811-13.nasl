#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201811-13.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(119133);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id("CVE-2017-16541", "CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12361", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12367", "CVE-2018-12371", "CVE-2018-12372", "CVE-2018-12373", "CVE-2018-12374", "CVE-2018-12376", "CVE-2018-12377", "CVE-2018-12378", "CVE-2018-12379", "CVE-2018-12383", "CVE-2018-12385", "CVE-2018-12389", "CVE-2018-12390", "CVE-2018-12391", "CVE-2018-12392", "CVE-2018-12393", "CVE-2018-5125", "CVE-2018-5127", "CVE-2018-5129", "CVE-2018-5144", "CVE-2018-5145", "CVE-2018-5146", "CVE-2018-5150", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5156", "CVE-2018-5159", "CVE-2018-5161", "CVE-2018-5162", "CVE-2018-5168", "CVE-2018-5170", "CVE-2018-5178", "CVE-2018-5183", "CVE-2018-5184", "CVE-2018-5185", "CVE-2018-5187", "CVE-2018-5188");
  script_xref(name:"GLSA", value:"201811-13");

  script_name(english:"GLSA-201811-13 : Mozilla Thunderbird: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201811-13
(Mozilla Thunderbird: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Mozilla Thunderbird.
      Please review the referenced Mozilla Foundation Security Advisories and
      CVE identifiers below for details.
  
Impact :

    A remote attacker may be able to execute arbitrary code, cause a Denial
      of Service condition, obtain sensitive information, or conduct Cross-Site
      Request Forgery (CSRF).
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201811-13"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Thunderbird users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=mail-client/thunderbird-60.3.0'
    All Thunderbird binary users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=mail-client/thunderbird-bin-60.3.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12391");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (qpkg_check(package:"mail-client/thunderbird", unaffected:make_list("ge 60.3.0"), vulnerable:make_list("lt 60.3.0"))) flag++;
if (qpkg_check(package:"mail-client/thunderbird-bin", unaffected:make_list("ge 60.3.0"), vulnerable:make_list("lt 60.3.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Thunderbird");
}
