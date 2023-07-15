#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-38.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164534);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/31");

  script_cve_id(
    "CVE-2022-38472",
    "CVE-2022-38473",
    "CVE-2022-38476",
    "CVE-2022-38477",
    "CVE-2022-38478"
  );

  script_name(english:"GLSA-202208-38 : Mozilla Thunderbird: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-38 (Mozilla Thunderbird: Multiple
Vulnerabilities)

  - An attacker could have abused XSLT error handling to associate attacker-controlled content with another
    origin which was displayed in the address bar. This could have been used to fool the user into submitting
    data intended for the spoofed origin.  (CVE-2022-38472)

  - Mozilla: Cross-origin XSLT Documents would have inherited the parent's permissions (CVE-2022-38473)

  - A data race could occur in the <code>PK11ChangePW</code> function, potentially leading to a use-after-free
    vulnerability.  In Thunderbird, this lock protected the data when a user changed their master password.
    (CVE-2022-38476)

  - Mozilla developer Nika Layzell and the Mozilla Fuzzing Team reported memory safety bugs present in
    Thunderbird 102.1. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code.  (CVE-2022-38477)

  - Members the Mozilla Fuzzing Team reported memory safety bugs present in Thunderbird 102.1 and Thunderbird
    91.12. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code.  (CVE-2022-38478)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-38");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=866217");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Thunderbird binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-bin-102.2.0
        
All Mozilla Thunderbird users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-102.2.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38478");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "mail-client/thunderbird",
    'unaffected' : make_list("ge 91.13.0", "lt 91.0.0"),
    'vulnerable' : make_list("lt 91.13.0")
  },
  {
    'name' : "mail-client/thunderbird-bin",
    'unaffected' : make_list("ge 91.13.0", "lt 91.0.0"),
    'vulnerable' : make_list("lt 91.13.0")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

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
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Thunderbird");
}
