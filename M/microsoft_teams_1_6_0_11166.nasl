#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175408);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/15");

  script_cve_id("CVE-2023-24881");
  script_xref(name:"IAVA", value:"2023-A-0247");

  script_name(english:"Microsoft Teams < 1.6.0.11166 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The version of Microsoft Teams installed on the remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Teams installed on the remote Windows host is version prior to 1.6.0.11166. It is, therefore,
affected by an information disclosure vulnerability. An unauthenticated, remote attacker can exploit this to disclose
potentially sensitive information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://learn.microsoft.com/en-us/officeupdates/teams-app-versioning");
  script_set_attribute(attribute:"see_also", value:"https://learn.microsoft.com/en-us/microsoftteams/teams-client-update");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24881");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Teams 1.6.0.11166 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24881");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:teams");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_teams_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Teams");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Microsoft Teams', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '1.6.0.11166' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
