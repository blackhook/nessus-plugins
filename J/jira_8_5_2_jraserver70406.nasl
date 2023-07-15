#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135765);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-20401");

  script_name(english:"Atlassian Jira 7.6 < 8.5.2 XSRF (JRASERVER-70406)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Atlassian Jira hosted on the remote web server is
version 7.6.x prior to 8.5.2. It is, therefore, affected by a cross-site request forgery vulnerability due to flaws in
various installation setup resources. An unauthenticated, remote attacker can exploit this issue, by tricking a user
into visiting a specially crafted web page, allowing the attacker to configure a Jira instance, which has not yet
finished being installed.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://jira.atlassian.com/browse/JRASERVER-70406?src=confmacro
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cdb2c5c");
  # https://confluence.atlassian.com/jirasoftware/issues-resolved-in-8-5-2-983794325.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32d63e1a");
  # https://confluence.atlassian.com/jirasoftware/issues-resolved-in-8-6-0-983794874.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15ffd13d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira version 8.5.2, 8.6.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20401");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

constraints = [
  { 'min_version' : '7.6', 'fixed_version' : '8.5.2' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xsrf:TRUE});
