#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-28.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(176195);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2017-18640",
    "CVE-2022-38749",
    "CVE-2022-38750",
    "CVE-2022-38751",
    "CVE-2022-38752"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"GLSA-202305-28 : snakeyaml: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-28 (snakeyaml: Multiple Vulnerabilities)

  - The Alias feature in SnakeYAML before 1.26 allows entity expansion during a load operation, a related
    issue to CVE-2003-1564. (CVE-2017-18640)

  - Using snakeYAML to parse untrusted YAML files may be vulnerable to Denial of Service attacks (DOS). If the
    parser is running on user supplied input, an attacker may supply content that causes the parser to crash
    by stackoverflow. (CVE-2022-38749, CVE-2022-38750, CVE-2022-38751)

  - Using snakeYAML to parse untrusted YAML files may be vulnerable to Denial of Service attacks (DOS). If the
    parser is running on user supplied input, an attacker may supply content that causes the parser to crash
    by stack-overflow. (CVE-2022-38752)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-28");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=776796");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=868621");
  script_set_attribute(attribute:"solution", value:
"All snakeyaml users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-java/snakeyaml-1.33");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18640");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:snakeyaml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'dev-java/snakeyaml',
    'unaffected' : make_list("ge 1.33"),
    'vulnerable' : make_list("lt 1.33")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'snakeyaml');
}
