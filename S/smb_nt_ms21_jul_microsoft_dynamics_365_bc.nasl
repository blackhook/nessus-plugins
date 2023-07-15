#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151603);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2021-34474");
  script_xref(name:"MSKB", value:"5004715");
  script_xref(name:"MSKB", value:"5004716");
  script_xref(name:"MSKB", value:"5004717");
  script_xref(name:"MSFT", value:"MS21-5004715");
  script_xref(name:"MSFT", value:"MS21-5004716");
  script_xref(name:"MSFT", value:"MS21-5004717");
  script_xref(name:"IAVA", value:"2021-A-0313-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 Business Central (July 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update. It is, therefore, affected by a
Remote Code Execution vulnerability. An authenticated attacker can exploit this, to execute arbitrary commands.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5004715");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5004716");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5004717");
  script_set_attribute(attribute:"solution", value:
"Update Microsoft Dynamics 365 Business Central to 16.14 for 2020 Release Wave 1, 17.8 for 2020 Release Wave 2, 18.3 for 2021 Release Wave 1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34474");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_business_central_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Business Central Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics 365 Business Central Server';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '16.0', 'fixed_version' : '16.0.27253.0', 'fixed_display' : 'Update 16.14 for Microsoft Dynamics 365 Business Central 2020 Release Wave 1' },
  { 'min_version' : '17.0', 'fixed_version' : '17.0.27235.0', 'fixed_display' : 'Update 17.8 for Microsoft Dynamics 365 Business Central 2020 Release Wave 2' },
  { 'min_version' : '18.0', 'fixed_version' : '18.0.27469.0', 'fixed_display' : 'Update 18.3 for Microsoft Dynamics 365 Business Central 2021 Release Wave 1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
