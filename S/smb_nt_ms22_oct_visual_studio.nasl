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
  script_id(166116);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/01");

  script_cve_id("CVE-2022-41032");
  script_xref(name:"IAVA", value:"2022-A-0413-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (Oct 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"An elevation of privilege vulnerability exists in the Microsoft Visual Studio application installed on the host. A
local attacker can gain the privileges of the user running the Microsoft Visual Studio application.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#1736--visual-studio-2022-version-1736
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f78495d");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2#1729--visual-studio-2022-version-1729
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1e58262");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0#17015--visual-studio-2022-version-17015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a882854");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9#--visual-studio-2019-version-16926-
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bbc940f");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#release-notes-icon-visual-studio-2019-version-161120
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71f85dc2");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 16.9.26 for Visual Studio 2019
        - Update 16.11.20 for Visual Studio 2019
        - Update 17.0.15 for Visual Studio 2022
        - Update 17.2.9 for Visual Studio 2022
        - Update 17.3.6 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.9.32930.78', 'fixed_display': '16.9.32930.78 (16.9.26)'},
  {'product': '2019', 'min_version': '16.10', 'fixed_version': '16.11.32929.386', 'fixed_display': '16.11.32929.386 (16.11.20)'},
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-history
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.32929.387', 'fixed_display': '17.0.32929.387 (17.0.15)'},
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.32929.388', 'fixed_display': '17.2.32929.388 (17.2.9)'},
  {'product': '2022', 'min_version': '17.3', 'fixed_version': '17.3.32929.385', 'fixed_display': '17.3.32929.385 (17.3.6)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_WARNING
);
