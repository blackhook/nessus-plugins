#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155627);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-21684");

  script_name(english:"Jenkins Git Plugin < 4.8.3 XSS");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of the Jenkins Git Plugin running on the remote web
server is prior to 4.8.3. It is, therefore, affected by a cross-site scripting vulnerability due to it not escaping the
Git SHA-1 checksum parameters provided to commit notifications when displaying them in a build cause, resulting in a
stored cross-site scripting (XSS) vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2021-10-06");
  script_set_attribute(attribute:"solution", value:
"Upgrade the Jenkins Git Plugin to version 4.8.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21684");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var plugin_list_and_constraints = [
  { 'plugin' : 'Jenkins Git plugin', 'fixed_version' : '4.8.3' }
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:plugin_list_and_constraints);

vcf::jenkins::plugin::check_version_and_report(app_info:app_info, constraints:plugin_list_and_constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
