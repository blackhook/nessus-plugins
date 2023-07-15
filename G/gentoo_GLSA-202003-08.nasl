#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202003-08.
#
# The advisory text is Copyright (C) 2001-2022 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(134475);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2019-13723", "CVE-2019-13724", "CVE-2019-13725", "CVE-2019-13726", "CVE-2019-13727", "CVE-2019-13728", "CVE-2019-13729", "CVE-2019-13730", "CVE-2019-13732", "CVE-2019-13734", "CVE-2019-13735", "CVE-2019-13736", "CVE-2019-13737", "CVE-2019-13738", "CVE-2019-13739", "CVE-2019-13740", "CVE-2019-13741", "CVE-2019-13742", "CVE-2019-13743", "CVE-2019-13744", "CVE-2019-13745", "CVE-2019-13746", "CVE-2019-13747", "CVE-2019-13748", "CVE-2019-13749", "CVE-2019-13750", "CVE-2019-13751", "CVE-2019-13752", "CVE-2019-13753", "CVE-2019-13754", "CVE-2019-13755", "CVE-2019-13756", "CVE-2019-13757", "CVE-2019-13758", "CVE-2019-13759", "CVE-2019-13761", "CVE-2019-13762", "CVE-2019-13763", "CVE-2019-13764", "CVE-2019-13767", "CVE-2020-6377", "CVE-2020-6378", "CVE-2020-6379", "CVE-2020-6380", "CVE-2020-6381", "CVE-2020-6382", "CVE-2020-6385", "CVE-2020-6387", "CVE-2020-6388", "CVE-2020-6389", "CVE-2020-6390", "CVE-2020-6391", "CVE-2020-6392", "CVE-2020-6393", "CVE-2020-6394", "CVE-2020-6395", "CVE-2020-6396", "CVE-2020-6397", "CVE-2020-6398", "CVE-2020-6399", "CVE-2020-6400", "CVE-2020-6401", "CVE-2020-6402", "CVE-2020-6403", "CVE-2020-6404", "CVE-2020-6406", "CVE-2020-6407", "CVE-2020-6408", "CVE-2020-6409", "CVE-2020-6410", "CVE-2020-6411", "CVE-2020-6412", "CVE-2020-6413", "CVE-2020-6414", "CVE-2020-6415", "CVE-2020-6416", "CVE-2020-6418", "CVE-2020-6420");
  script_xref(name:"GLSA", value:"202003-08");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0023");

  script_name(english:"GLSA-202003-08 : Chromium, Google Chrome: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-202003-08
(Chromium, Google Chrome: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and Google
      Chrome. Please review the referenced CVE identifiers and Google Chrome
      Releases for details.
  
Impact :

    A remote attacker could execute arbitrary code, escalate privileges,
      obtain sensitive information, spoof an URL or cause a Denial of Service
      condition.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/202003-08"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-80.0.3987.132'
    All Google Chrome users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/google-chrome-80.0.3987.132'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6420");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome 80 JSCreate side-effect type confusion exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/13");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 80.0.3987.132"), vulnerable:make_list("lt 80.0.3987.132"))) flag++;
if (qpkg_check(package:"www-client/google-chrome", unaffected:make_list("ge 80.0.3987.132"), vulnerable:make_list("lt 80.0.3987.132"))) flag++;

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
