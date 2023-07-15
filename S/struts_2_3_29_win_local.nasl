#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91812);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-0785",
    "CVE-2016-4430",
    "CVE-2016-4431",
    "CVE-2016-4433",
    "CVE-2016-4436",
    "CVE-2016-4438",
    "CVE-2016-4461"
  );
  script_bugtraq_id(
    85066,
    91275,
    91277,
    91280,
    91281,
    91282,
    91284
  );

  script_name(english:"Apache Struts 2.x < 2.3.29 Multiple Vulnerabilities (S2-035 - S2-040)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web application that uses a Java
framework that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote Windows host is 2.x
prior to 2.3.29. It is, therefore, affected by the following
vulnerabilities :

  - A remote code execution vulnerability exists due to
    erroneously performing double OGNL evaluation of
    attribute values assigned to certain tags. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary code.
    (CVE-2016-0785)

  - A cross-site request forgery (XSRF) vulnerability exists
    due to improper validation of session tokens. An
    unauthenticated, remote attacker can exploit this, via a
    malicious OGNL expression, to bypass token validation
    and perform an XSRF attack. (CVE-2016-4430)

  - Multiple input validation issues exists that allow
    internal security mechanisms to be bypassed, allowing
    the manipulation of a return string which can be used to
    redirect users to a malicious website. This affects both
    the default action method the 'getter' action method.
    (CVE-2016-4431, CVE-2016-4433)

  - An unspecified flaw exists that is triggered during the
    cleanup of action names. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    payload, to perform unspecified actions. (CVE-2016-4436)

  - A remote code execution vulnerability exists in the REST
    plugin due to improper handling of OGNL expressions. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted OGNL expression, to execute
    arbitrary code. (CVE-2016-4438)

  - A remote code execution vulnerability exists in user tag
    attributes due to improper handling of OGNL expressions. 
    An unauthenticated, remote attacker can exploit this, 
    via a specially crafted double OGNL evaluation, to 
    execute arbitrary code. (CVE-2016-4461)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-035.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-036.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-037.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-038.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-039.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-040.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/version-notes-2329.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.29 or later. Alternatively,
apply the workarounds referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4461");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Struts REST Plugin OGNL Expression Handling RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include('vcf.inc');


app_info = vcf::combined_get_app_info(app:'Apache Struts');
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '2.0.0', 'max_version' : '2.3.28.1', 'fixed_display' : '2.3.29' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xsrf:TRUE});

