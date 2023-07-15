#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132320);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id("CVE-2019-15011", "CVE-2019-15013");

  script_name(english:"Atlassian JIRA < 8.4.2 Information disclosure in Application links plugin");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian JIRA hosted on the remote web server is 8.4.x prior
to 8.4.2. It is, therefore, affected by multiple vulnerabilities:

  - An information disclosure vulnerability in the listEntityLinks
    servlet resource of the Application links plugin discloses
    application link information to non-admin users via a missing
    permissions check. (CVE-2019-15011)

  - The WorkflowResource class removeStatus method in Jira before
    version 7.13.12, from version 8.0.0 before version 8.4.3, and
    from version 8.5.0 before version 8.5.2 allows authenticated
    remote attackers who do not have project administration access
    to remove a configured issue status from a project via a
    missing authorization check. (CVE-2019-15013)");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRASERVER-70409");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 8.4.2 / 8.5.0");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15013");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_detect.nasl", "atlassian_jira_win_installed.nbin", "atlassian_jira_nix_installed.nbin");
  script_require_keys("installed_sw/Atlassian JIRA");

  exit(0);
}

include('vcf.inc');


app_info = vcf::combined_get_app_info(app:'Atlassian JIRA');

constraints = [
  { 'fixed_version' : '8.4.2', 'fixed_display' : '8.4.2 / 8.5.0' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
