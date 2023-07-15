#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155000);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-40442", "CVE-2021-41368", "CVE-2021-42292");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/01");
  script_xref(name:"MSKB", value:"5002038");
  script_xref(name:"MSKB", value:"4486670");
  script_xref(name:"MSKB", value:"5002035");
  script_xref(name:"MSKB", value:"5002032");
  script_xref(name:"MSFT", value:"MS21-5002038");
  script_xref(name:"MSFT", value:"MS21-4486670");
  script_xref(name:"MSFT", value:"MS21-5002035");
  script_xref(name:"MSFT", value:"MS21-5002032");
  script_xref(name:"IAVA", value:"2021-A-0546-S");

  script_name(english:"Security Updates for Microsoft Office Products (November 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - A security feature bypass vulnerability exists. An attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising the integrity of the system/application.
    (CVE-2021-42292)

  - Two remote code execution vulnerabilities. An attacker can exploit this to bypass authentication and
    execute unauthorized arbitrary commands. (CVE-2021-40442, CVE-2021-41368)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4486670");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002032");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002035");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002038");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4486670
  -KB5002032
  -KB5002038
  -KB5002035");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42292");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/09");

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

var bulletin = 'MS21-11';
var kbs = make_list(
  '4886670',
  '5002032',
  '5002035',
  '5002038'
);
var severity = SECURITY_WARNING;

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office', kbs:kbs, bulletin:bulletin, severity:severity);

var constraints = [
  {'product' : 'Microsoft Office 2013 SP1', 'kb':'5002038', 'file':'acecore.dll', 'fixed_version': '15.0.5397.1000'},
  {'product' : 'Microsoft Office 2013 SP1', 'kb':'5002035', 'file':'mso.dll', 'fixed_version': '15.0.5397.1001'},
  {'product' : 'Microsoft Office 2016', 'kb':'4886670', 'file':'mso99lwin32client.dll', 'fixed_version': '16.0.5239.1001'},
  {'product' : 'Microsoft Office 2016', 'kb':'5002032', 'file':'acecore.dll', 'fixed_version': '16.0.5239.1000'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'Excel'
);

