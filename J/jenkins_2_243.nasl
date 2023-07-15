#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139734);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-17638");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Jenkins < 2.235.5 LTS / 2.243 Information Disclosure Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is 2.224 through 2.242 or is a version of Jenkins LTS
 2.222.1 through 2.235.4. It is, therefore, affected by an information disclosure vulnerability exists due to an vulnerable Jetty 9.4.27
 library. An unauthenticated, remote attacker can exploit this to disclose potentially sensitive information intended for
 other users.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2020-08-17/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.243 or later, Jenkins LTS to version 2.235.5 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17638");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'min_version' : '2.224',    'fixed_version' : '2.243',    'fixed_display' : '2.235.5 LTS / 2.243',  'edition' : 'Open Source' },
  { 'min_version' : '2.222.1',  'fixed_version' : '2.235.5',  'fixed_display' : '2.235.5 LTS / 2.243',  'edition' : 'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
