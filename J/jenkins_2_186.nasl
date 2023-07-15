#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127053);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-10352", "CVE-2019-10353", "CVE-2019-10354");
  script_bugtraq_id(109299, 109373);
  script_xref(name:"TRA", value:"TRA-2019-35");

  script_name(english:"Jenkins < 2.176.2 LTS / 2.186 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to 2.186 or is a version of Jenkins LTS prior to
2.176.2. It is, therefore, affected by multiple vulnerabilities:

  - An arbitrary file write vulnerability exists due to an incomplete fix for SECURITY-1074, the improper
    validation of the file parameter definition. An authenticated, remote attacker can exploit this, via a
    file name with a relative path escaping the base directory, to write arbitrary files on the remote host.
    (CVE-2019-10352)

  - A security bypass vulnerability exists due to insufficent validaiton of CSRF tokens. An unauthenticated,
    remote attacker can exploit this, after obtaining the CSRF token of another user, to bypass CSRF
    protections and implement a CSRF attack. (CVE-2019-10353)

  - An information disclosure vulnerability exists in the Stapler web framework due to inadequit permission
    control of view fragments. An authenticated, remote attacker can exploit this, to disclose potentially
    sensitive information. (CVE-2019-10354)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2019-07-17/");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2019-35");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.186 or later, Jenkins LTS to version 2.176.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10353");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");

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
  { 'fixed_version' : '2.186',    'fixed_display' : '2.176.2 LTS / 2.186',  'edition' : 'Open Source' },
  { 'fixed_version' : '2.176.2',  'fixed_display' : '2.176.2 LTS / 2.186',  'edition' : 'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
