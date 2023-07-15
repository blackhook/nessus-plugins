#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202202-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158198);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/03");

  script_cve_id(
    "CVE-2022-0452",
    "CVE-2022-0453",
    "CVE-2022-0454",
    "CVE-2022-0455",
    "CVE-2022-0456",
    "CVE-2022-0457",
    "CVE-2022-0458",
    "CVE-2022-0459",
    "CVE-2022-0460",
    "CVE-2022-0461",
    "CVE-2022-0462",
    "CVE-2022-0463",
    "CVE-2022-0464",
    "CVE-2022-0465",
    "CVE-2022-0466",
    "CVE-2022-0467",
    "CVE-2022-0468",
    "CVE-2022-0469",
    "CVE-2022-0470",
    "CVE-2022-0603",
    "CVE-2022-0604",
    "CVE-2022-0605",
    "CVE-2022-0606",
    "CVE-2022-0607",
    "CVE-2022-0608",
    "CVE-2022-0609",
    "CVE-2022-0610"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/01");

  script_name(english:"GLSA-202202-02 : Chromium, Google Chrome: Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202202-02 (Chromium, Google Chrome: Multiple
vulnerabilities)

  - Use after free in Animation in Google Chrome prior to 98.0.4758.102 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0609)

  - Use after free in Safe Browsing in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2022-0452)

  - Use after free in Reader Mode in Google Chrome prior to 98.0.4758.80 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2022-0453)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0454)

  - Inappropriate implementation in Full Screen Mode in Google Chrome on Android prior to 98.0.4758.80 allowed
    a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-0455)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202202-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=832559");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=833432");
  script_set_attribute(attribute:"solution", value:
"All Chromium users should upgrade to the latest version:

              # emerge --sync
              # emerge --ask --oneshot --verbose >=www-client/chromium-98.0.4758.102
            
All Google Chrome users should upgrade to the latest version:

              # emerge --sync
              # emerge --ask --oneshot --verbose >=www-client/google-chrome-98.0.4758.102");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0609");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:google-chrome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var flag = 0;

var packages = [
  {
    'name' : "www-client/chromium",
    'unaffected' : make_list("ge 98.0.4758.102"),
    'vulnerable' : make_list("lt 98.0.4758.102")
  },
  {
    'name' : "www-client/google-chrome",
    'unaffected' : make_list("ge 98.0.4758.102"),
    'vulnerable' : make_list("lt 98.0.4758.102")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / Google Chrome");
}
