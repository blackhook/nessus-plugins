#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202209-09.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(165442);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/25");

  script_cve_id(
    "CVE-2018-25047",
    "CVE-2021-21408",
    "CVE-2021-29454",
    "CVE-2022-29221"
  );

  script_name(english:"GLSA-202209-09 : Smarty: Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202209-09 (Smarty: Multiple vulnerabilities)

  - In Smarty before 3.1.47 and 4.x before 4.2.1, libs/plugins/function.mailto.php allows XSS. A web page that
    uses smarty_function_mailto, and that could be parameterized using GET or POST input parameters, could
    allow injection of JavaScript code by a user. (CVE-2018-25047)

  - Smarty is a template engine for PHP, facilitating the separation of presentation (HTML/CSS) from
    application logic. Prior to versions 3.1.43 and 4.0.3, template authors could run restricted static php
    methods. Users should upgrade to version 3.1.43 or 4.0.3 to receive a patch. (CVE-2021-21408)

  - Smarty is a template engine for PHP, facilitating the separation of presentation (HTML/CSS) from
    application logic. Prior to versions 3.1.42 and 4.0.2, template authors could run arbitrary PHP code by
    crafting a malicious math string. If a math string was passed through as user provided data to the math
    function, external users could run arbitrary PHP code by crafting a malicious math string. Users should
    upgrade to version 3.1.42 or 4.0.2 to receive a patch. (CVE-2021-29454)

  - Smarty is a template engine for PHP, facilitating the separation of presentation (HTML/CSS) from
    application logic. Prior to versions 3.1.45 and 4.1.1, template authors could inject php code by choosing
    a malicious {block} name or {include} file name. Sites that cannot fully trust template authors should
    upgrade to versions 3.1.45 or 4.1.1 to receive a patch for this issue. There are currently no known
    workarounds. (CVE-2022-29221)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202209-09");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=830980");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=845180");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=870100");
  script_set_attribute(attribute:"solution", value:
"All Smarty users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-php/smarty-4.2.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29221");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:smarty");
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
    'name' : "dev-php/smarty",
    'unaffected' : make_list("ge 4.2.1", "lt 4.0.0"),
    'vulnerable' : make_list("lt 4.2.1")
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
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Smarty");
}
