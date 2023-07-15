#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('compat.inc');

if (description)
{
  script_id(169968);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2023-21538");
  script_xref(name:"IAVA", value:"2023-A-0028-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (Jan 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"A denial of service vulnerability exists in .NET 6.0 where a malicious client could cause a 
stack overflow which may result in a denial of service attack when an attacker sends an invalid 
request to an exposed endpoint.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.4.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f45c1b3");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.23
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0965922");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 16.11.23 for Visual Studio 2019
        - Update 17.4.4 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21538");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::visual_studio::get_app_info();

var constraints = [
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/history
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.11.33214.272', 'fixed_display': '16.11.33214.272 (16.11.23)'},
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-history
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.4.33213.308', 'fixed_display': '17.4.33213.308 (17.4.4)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
