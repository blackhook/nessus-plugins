#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168665);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/19");

  script_cve_id("CVE-2022-41120");

  script_name(english:"Microsoft Windows Sysinternals Sysmon < 14.13 Elevation of Privilege (November 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"An elevation of privilege vulnerability exists in Microsoft Windows Sysinternals Sysmon 
prior to 14.13. A locally authenticated attacker who successfully exploited the vulnerability 
could manipulate information on the Sysinternals services to achieve elevation from local user 
to SYSTEM admin.

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41120
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2feb4fb7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sysinternals Sysmon version 14.13, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41120");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:sysinternals_sysmon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sysmon_win_installed.nbin");
  script_require_keys("installed_sw/Sysmon");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Sysmon');

var constraints = [
    { 'min_version': '12.0', 'fixed_version' : '14.1.3.0', 'fixed_display': '14.13'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
