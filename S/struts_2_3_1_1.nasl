#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117404);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Apache Struts 2.x < 2.3.18 Multiple Critical Vulnerabilities (S2-008)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host uses a Java framework that is affected by multiple critical
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 2.x prior to 2.3.18. It, therefore, is affected by multiple
critical vulnerabilities:

  - A remote code execution vulnerability exists in ExceptionDelegator due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit this issue, to bypass authentication and execute arbitrary
    commands.

  - A remote code execution vulnerability exists in CookieInterceptor due to improper validation for parameter names. An
    unauthenticated, remote attacker can exploit this issue, to execute arbitrary system commands with static method
    access to Java functions.

  - An arbitrary file write vulnerability exists in ParameterInterceptor due to improper access restrictions. An 
    unauthenticated, remote attacker can exploit this issue, to create and overwrite arbitrary files.

  - A remote code execution vulnerability exists in DebugginInterceptor when running in developer mode. An
    unauthenticated, remote attacker can exploit this issue, to execute arbitrary commands.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://cwiki.apache.org/confluence/display/WW/S2-008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecedf586");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.18 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"remote command execution");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Apache Struts');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '2.0.0', 'fixed_version' : '2.3.18' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
