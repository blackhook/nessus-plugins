#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133854);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-20098", "CVE-2019-20099");

  script_name(english:"Atlassian JIRA 7.x >= 7.6 / 8.x < 8.5.4 / 8.6.x < 8.6.2 Multiple CSRF");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially affected by multiple cross-site request forgery vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian JIRA hosted on the remote web server is 7.x greater than or
equal to 7.6, 8.x prior to 8.5.4, or 8.6.x prior to 8.6.2. It is,
therefore, affected by multiple vulnerabilities:

  - An input-validation flaw exists related to the
    VerifySmtpServerConnection!add.jspa component that
    allows cross-site request forgery attacks.
    (CVE-2019-20098)

  - An input-validation flaw exists related to the
    VerifyPopServerConnection!add.jspa component that
    allows cross-site request forgery attacks.
    (CVE-2019-20099)");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-70605");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-70606");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 8.5.4, 8.6.2, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20099");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/21");

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
  { 'min_version':'7.6', 'fixed_version' : '8.5.4', 'fixed_display': '8.5.4 / 8.6.2 / 8.7.0' },
  { 'min_version':'8.6', 'fixed_version' : '8.6.2', 'fixed_display': '8.6.2 / 8.7.0' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xsrf:TRUE});
