#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168737);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-41127");
  script_xref(name:"MSKB", value:"5021671");
  script_xref(name:"MSFT", value:"MS22-5021671");
  script_xref(name:"IAVA", value:"2022-A-0531-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 Business Central (December 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update. It is, therefore, affected by an
remote code execution vulnerability. A remote attacker with admin privileges can exploit this vulnerability to
execute malicious instructions on their behalf.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41127
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8735fd30");
  # https://support.microsoft.com/en-gb/topic/update-20-8-for-microsoft-dynamics-365-business-central-on-premises-2022-release-wave-1-application-build-20-8-49971-platform-build-20-0-49947-5feef8d3-7e3f-4b31-ad1c-a778df4ac1a2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b721791");
  script_set_attribute(attribute:"solution", value:
"Update Microsoft Dynamics 365 Business Central to 20.8 for 2022 Release Wave 1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41127");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_business_central_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Business Central Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics 365 Business Central Server';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '14.0', 'fixed_version' : '14.43.49498.0', 'fixed_display' : 'Update 14.43 for Microsoft Dynamics 365 Business Central April 2019 On-Premises' },  
  { 'min_version' : '15.0', 'fixed_version' : '15.17.48428.0', 'fixed_display' : 'Update 15.17 for Microsoft Dynamics 365 Business Central April 2019 On-Premises' },  
  { 'min_version' : '16.0', 'fixed_version' : '16.19.49472.0', 'fixed_display' : 'Update 16.19 for Microsoft Dynamics 365 Business Central 2020 Release Wave 1' },  
  { 'min_version' : '17.0', 'fixed_version' : '17.17.49465.0', 'fixed_display' : 'Update 17.17 for Microsoft Dynamics 365 Business Central 2020 Release Wave 2' },  
  { 'min_version' : '18.0', 'fixed_version' : '18.18.49460.0', 'fixed_display' : 'Update 18.18 for Microsoft Dynamics 365 Business Central 2021 Release Wave 1' },  
  { 'min_version' : '19.0', 'fixed_version' : '19.14.49947.0', 'fixed_display' : 'Update 19.14 for Microsoft Dynamics 365 Business Central 2021 Release Wave 2' },  
  { 'min_version' : '20.0', 'fixed_version' : '20.8.49971.0', 'fixed_display' : 'Update 20.8 for Microsoft Dynamics 365 Business Central 2022 Release Wave 1' },
  { 'min_version' : '21.0', 'fixed_version' : '21.2.49990.0', 'fixed_display' : 'Update 21.2 for Microsoft Dynamics 365 Business Central 2022 Release Wave 2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);