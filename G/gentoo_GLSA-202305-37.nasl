#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-37.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(176471);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/31");

  script_cve_id(
    "CVE-2022-42252",
    "CVE-2022-45143",
    "CVE-2023-24998",
    "CVE-2023-28709"
  );

  script_name(english:"GLSA-202305-37 : Apache Tomcat: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-37 (Apache Tomcat: Multiple Vulnerabilities)

  - If Apache Tomcat 8.5.0 to 8.5.82, 9.0.0-M1 to 9.0.67, 10.0.0-M1 to 10.0.26 or 10.1.0-M1 to 10.1.0 was
    configured to ignore invalid HTTP headers via setting rejectIllegalHeader to false (the default for 8.5.x
    only), Tomcat did not reject a request containing an invalid Content-Length header making a request
    smuggling attack possible if Tomcat was located behind a reverse proxy that also failed to reject the
    request with the invalid header. (CVE-2022-42252)

  - The JsonErrorReportValve in Apache Tomcat 8.5.83, 9.0.40 to 9.0.68 and 10.1.0-M1 to 10.1.1 did not escape
    the type, message or description values. In some circumstances these are constructed from user provided
    data and it was therefore possible for users to supply values that invalidated or manipulated the JSON
    output. (CVE-2022-45143)

  - Apache Commons FileUpload before 1.5 does not limit the number of request parts to be processed resulting
    in the possibility of an attacker triggering a DoS with a malicious upload or series of uploads. Note
    that, like all of the file upload limits, the new configuration option (FileUploadBase#setFileCountMax) is
    not enabled by default and must be explicitly configured. (CVE-2023-24998)

  - The fix for CVE-2023-24998 was incomplete for Apache Tomcat 11.0.0-M2 to 11.0.0-M4, 10.1.5 to 10.1.7,
    9.0.71 to 9.0.73 and 8.5.85 to 8.5.87. If non-default HTTP connector settings were used such that the
    maxParameterCount could be reached using query string parameters and a request was submitted that supplied
    exactly maxParameterCount parameters in the query string, the limit for uploaded request parts could be
    bypassed with the potential for a denial of service to occur. (CVE-2023-28709)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-37");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=878911");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=889596");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=896370");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=907387");
  script_set_attribute(attribute:"solution", value:
"All Apache Tomcat users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-servers/tomcat-10.1.8");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tomcat");
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
    'name' : 'www-servers/tomcat',
    'unaffected' : make_list("ge 10.1.8", "lt 10.0.0"),
    'vulnerable' : make_list("lt 10.1.8")
  },
  {
    'name' : 'www-servers/tomcat',
    'unaffected' : make_list("ge 8.5.88", "lt 8.0.0"),
    'vulnerable' : make_list("lt 8.5.88")
  },
  {
    'name' : 'www-servers/tomcat',
    'unaffected' : make_list("ge 9.0.74", "lt 9.0.0"),
    'vulnerable' : make_list("lt 9.0.74")
  }
];

foreach var package( packages ) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Apache Tomcat');
}
