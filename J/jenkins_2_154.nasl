#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119500);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-1000861",
    "CVE-2018-1000862",
    "CVE-2018-1000863",
    "CVE-2018-1000864"
  );
  script_xref(name:"TRA", value:"TRA-2018-43");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/10");

  script_name(english:"Jenkins < 2.138.4 LTS / 2.150.1 LTS / 2.154 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to
2.154 or is a version of Jenkins LTS prior to 2.138.4 or 2.150.1. It is,
therefore, affected by multiple vulnerabilities:

  - A command execution vulnerability exists in the Stapler
    web framework used in Jenkins due to certain methods 
    being invoked via crafted URLs. An unauthenticated, 
    remote attacker can exploit this to invoke methods 
    never intended to be invoked in this way, which could
    potentially lead to command execution. 

  - A denial of service (DoS) vulnerability exists in 
    Jenkins due to a forced migration of user records. 
    An unauthenticated, remote attacker can exploit 
    this issue, via submitting a crafted username to
    Jenkins login, which could potentially prevent
    valid users from being able to log in.

  - An arbitrary file read vulnerability exists in 
    Jenkins due to the workspace browser following
    symlinks outside the workspace. An attacker
    could exploit this to read arbitrary files 
    outside of the workspace and disclose sensitive 
    information.

  - A potential denial of service (DoS) vulnerability 
    exists in Jenkins due to an error in cron expression
    form validation. An attacker can exploit this issue, 
    via a crafted cron expression, to cause the application 
    to stop responding.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2018-12-05/");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-43");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.154 or later, Jenkins LTS to version
2.138.4, 2.150.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000861");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Jenkins ACL Bypass and Metaprogramming RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'fixed_version' : '2.154',    'fixed_display' : '2.138.4 LTS / 2.150.1 LTS / 2.154',  'edition' : 'Open Source' },
  { 'fixed_version' : '2.138.4',  'fixed_display' : '2.138.4 LTS / 2.150.1 LTS / 2.154',  'edition' : 'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
