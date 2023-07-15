#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(147218);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-24108",
    "CVE-2021-27054",
    "CVE-2021-27057",
    "CVE-2021-27059"
  );
  script_xref(name:"MSKB", value:"4493228");
  script_xref(name:"MSKB", value:"4493203");
  script_xref(name:"MSKB", value:"4504703");
  script_xref(name:"MSKB", value:"4493225");
  script_xref(name:"MSKB", value:"4493200");
  script_xref(name:"MSKB", value:"4493214");
  script_xref(name:"MSFT", value:"MS21-4493228");
  script_xref(name:"MSFT", value:"MS21-4493203");
  script_xref(name:"MSFT", value:"MS21-4504703");
  script_xref(name:"MSFT", value:"MS21-4493225");
  script_xref(name:"MSFT", value:"MS21-4493200");
  script_xref(name:"MSFT", value:"MS21-4493214");
  script_xref(name:"IAVA", value:"2021-A-0132-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Security Updates for Microsoft Office Products (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
They are affected by a remote code execution vulnerability. An attacker can exploit this to bypass 
authentication and execute unauthorized arbitrary commands. (CVE-2021-24108, CVE-2021-27054, 
CVE-2021-27057, CVE-2021-27059)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493228");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493203");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4504703");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493225");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493200");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493214");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4493228
  -KB4493203
  -KB4504703
  -KB4493225
  -KB4493200
  -KB4493214");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27059");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-27057");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS21-03';
var kbs = make_list(
  '4504703',
  '4493228',
  '4493203',
  '4493200',
  '4493225',
  '4493214'
);
var severity = SECURITY_HOLE;

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office', kbs:kbs, bulletin:bulletin, severity:severity);

var constraints = [
  {'product' : 'Microsoft Office 2010 SP2', 'kb':'4504703', 'file':'mso.dll', 'fixed_version': '14.0.7266.5000'},
  {'product' : 'Microsoft Office 2010 SP2', 'kb':'4493214', 'file':'graph.exe', 'fixed_version': '14.0.7266.5000'},
  {'product' : 'Microsoft Office 2013 SP1', 'kb':'4493228', 'file':'mso.dll', 'fixed_version': '15.0.5327.1000'},
  {'product' : 'Microsoft Office 2013 SP1', 'kb':'4493203', 'file':'graph.exe', 'fixed_version': '15.0.5327.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'4493200', 'file':'graph.exe', 'fixed_version': '16.0.5134.1000'},
  {'product' : 'Microsoft Office 2016', 'kb':'4493225', 'file':'mso.dll', 'fixed_version': '16.0.5134.1000'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Excel'
);

