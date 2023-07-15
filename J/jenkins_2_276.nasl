#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145533);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-21615");
  script_xref(name:"IAVA", value:"2021-A-0047-S");

  script_name(english:"Jenkins < 2.263.3 LTS / 2.276 TOCTOU");

  script_set_attribute(attribute:"synopsis", value:
"A job scheduling and management system hosted on the remote web server is affected by a time-of-check to time-of-use race condition.");
  script_set_attribute(attribute:"description", value:
"The version of Jenkins running on the remote web server is prior to 2.276 weekly or 2.263.3 LTS. It is, therefore,
affected by a time-of-check to time-of-use (TOCTOU) race condition that allows reading arbitrary files using the file
browser for workspaces and archived artifacts.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.jenkins.io/security/advisory/2021-01-26/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins to version 2.276 or later, Jenkins LTS to version 2.263.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21615");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'fixed_version' : '2.276',    'fixed_display' : '2.263.3 LTS / 2.276',  'edition' : 'Open Source' },
  { 'fixed_version' : '2.263.3',  'fixed_display' : '2.263.3 LTS / 2.276',  'edition' : 'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
