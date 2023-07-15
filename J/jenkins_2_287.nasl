#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148418);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2021-21639",
    "CVE-2021-21640",
    "CVE-2021-21641",
    "CVE-2021-22510",
    "CVE-2021-22511",
    "CVE-2021-22512",
    "CVE-2021-22513"
  );

  script_name(english:"Jenkins LTS < 2.277.2 / Jenkins weekly < 2.287 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
LTS prior to 2.277.2 or Jenkins weekly prior to 2.287. It is, therefore, affected by multiple vulnerabilities:

  - Jenkins 2.286 and earlier, LTS 2.277.1 and earlier does not validate the type of object created after
    loading the data submitted to the `config.xml` REST API endpoint of a node, allowing attackers with
    Computer/Configure permission to replace a node with one of a different type. (CVE-2021-21639)

  - Jenkins 2.286 and earlier, LTS 2.277.1 and earlier does not properly check that a newly created view has
    an allowed name, allowing attackers with View/Create permission to create views with invalid or already-
    used names. (CVE-2021-21640)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins promoted builds Plugin 3.9 and earlier allows
    attackers to to promote builds. (CVE-2021-21641)
    
  - Improper Certificate Validation vulnerability in Micro Focus Application Automation Tools Plugin - 
    Jenkins plugin. The vulnerability affects version 6.7 and earlier versions. The vulnerability could 
    allow unconditionally disabling of SSL/TLS certificates. (CVE-2021-22511)
    
  - Cross-Site Request Forgery (CSRF) vulnerability in Micro Focus Application Automation Tools Plugin - Jenkins 
    plugin. The vulnerability affects version 6.7 and earlier versions. The vulnerability could allow form 
    validation without permission checks. (CVE-2021-22512)
    
  - Missing Authorization vulnerability in Micro Focus Application Automation Tools Plugin - Jenkins plugin. 
    The vulnerability affects version 6.7 and earlier versions. The vulnerability could allow access without 
    permission checks. (CVE-2021-22513)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2021-04-07");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.287 or later or Jenkins LTS to version 2.277.2 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22511");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-22513");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'max_version' : '2.286',    'fixed_version' : '2.287',    'edition' : 'Open Source' },
  { 'max_version' : '2.277.1',  'fixed_version' : '2.277.2',  'edition' : 'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
