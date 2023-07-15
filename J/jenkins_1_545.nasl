#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72743);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-6372");
  script_bugtraq_id(63864);

  script_name(english:"Jenkins < 1.545 Subversion Plugin Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a job scheduling / management system that
is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins that is affected by an
information disclosure vulnerability that could allow a local attacker
to obtain passwords and SSH private key passphrases related to accessing
Subversion resources.");
  # https://wiki.jenkins.io/display/SECURITY/Jenkins+Security+Advisory+2013-11-20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e903dff9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins 1.545 or use the plugin update mechanism to obtain
Subversion plugin version 1.54 or greater.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

# Plugins can be updated independently,
# so scan must paranoid
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var constraints = [
  { 'fixed_version' : '1.545',    'edition':'Open Source' },
  { 'fixed_version' : '1.532.2',  'fixed_display' : 'Upgrade the Subversion plugin',  'edition':'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
