#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125734);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-1000192",
    "CVE-2018-1000193",
    "CVE-2018-1000194",
    "CVE-2018-1000195"
  );

  script_name(english:"Jenkins < 2.121 / < 2.107.3 (LTS) Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling and management system that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins that is prior to 2.121, or a version of Jenkins LTS prior to 2.107.3. 
It is, therefore, affected by the following vulnerabilities :

  - An information disclosure vulnerability exists in the AboutJenkins.java & ListPluginsCommand.java classes of 
    Jenkins. An unauthenticated, remote attacker can exploit this to disclose installed plugins on the remote server 
    (CVE-2018-1000192).

  - A directory traversal vulnerability exists in the FilePath.java & SoloFilePathFilter.java classes of Jenkins. An 
    unauthenticated, remote attacker can exploit this, by sending a URI that contains directory traversal characters, 
    to disclose the contents of files located outside of the server's restricted path (CVE-2018-1000194). 
    
  - A server-side request forgery (SSRF) vulnerability exists in the ZipExtractionInstaller.java class of Jenkins. An 
    attacker may exploit this to force Jenkins to send a HTTP get request to an arbitrary URL and glean what the 
    response code was (CVE-2018-1000195).");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2018-05-09/");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/changelog/");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/changelog-stable/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.121 or later. For Jenkins LTS, upgrade 
  to version 2.107.3 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000194");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/07");
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
  {'edition':'Open Source', 'fixed_version':'2.121'},
  {'edition':'Open Source LTS', 'fixed_version':'2.107.3'}
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
