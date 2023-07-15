#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125706);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-1000393",
    "CVE-2017-1000394",
    "CVE-2017-1000395",
    "CVE-2017-1000396",
    "CVE-2017-1000398",
    "CVE-2017-1000399",
    "CVE-2017-1000400",
    "CVE-2017-1000401"
  );
  script_bugtraq_id(
    104303,
    104304,
    104305,
    104306,
    104951
  );

  script_name(english:"Jenkins < 2.84 / < 2.73.2 (LTS) Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling and management system that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins that is prior to 2.84, or a version of Jenkins LTS prior to 2.73.2. 
It is, therefore, affected by the following vulnerabilities :
  
  - A remote command execution vulnerability exists in the launch method component due to insufficient default permissions 
    being set. An authenticated, remote attacker can exploit this to execute arbitrary commands (CVE-2017-1000393).

  - A denial of service (DoS) vulnerability exists in the commons-fileupload library bundled with Jenkins. An 
    unauthenticated, remote attacker can exploit this issue, by supplying a long boundary string, to cause the 
    application to stop responding. (CVE-2017-1000394).

  - An information disclosure vulnerability exists in the remote API component. An authenticated, remote attacker can 
    exploit this, by requesting data from unsecured API endpoints, to disclose potentially sensitive information about 
    users on the system (CVE-2017-1000395).");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2017-10-11/");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/changelog/");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/changelog-stable/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.84 or later. For Jenkins LTS, upgrade 
  to version 2.73.2 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000393");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  {'edition':'Open Source', 'fixed_version':'2.84'},
  {'edition':'Open Source LTS', 'fixed_version':'2.73.2'}
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
