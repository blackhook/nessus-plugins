#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
 ##

include('compat.inc');

if (description)
{
  script_id(174163);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id(
    "CVE-2023-28260",
    "CVE-2023-28262",
    "CVE-2023-28263",
    "CVE-2023-28296",
    "CVE-2023-28299"
  );
  script_xref(name:"IAVA", value:"2023-A-0184-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (Apr 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - .NET DLL Hijacking Remote Code Execution Vulnerability. (CVE-2023-28260)

  - Visual Studio Elevation of Privilege Vulnerability. (CVE-2023-28262)

  - Visual Studio Information Disclosure Vulnerability. (CVE-2023-28263)

  - Visual Studio Remote Code Execution Vulnerability. (CVE-2023-28296)

  - Visual Studio Spoofing Vulnerability. (CVE-2023-28299)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.5.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e749f95");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#17.4.7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92da7fb4");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2#17.2.15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f0b69ad");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0#17.0.21
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9d71e26");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.26
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5980d658");
  # https://learn.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.54
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3ad74f0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 15.9.54 for Visual Studio 2017
        - Update 16.11.26 for Visual Studio 2019
        - Update 17.0.21 for Visual Studio 2022
        - Update 17.2.15 for Visual Studio 2022
        - Update 17.4.7 for Visual Studio 2022
        - Update 17.5.4 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28296");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/12");

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
  {'product': '2017', 'min_version': '15.0', 'fixed_version': '15.9.33529.398', 'fixed_display': '15.9.33529.398 (15.9.54)'},
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.11.33529.622', 'fixed_display': '16.11.33529.622 (16.11.26)'},
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.33530.339', 'fixed_display': '17.0.33530.339 (17.0.21)'},
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.33530.394', 'fixed_display': '17.2.33530.394 (17.2.15)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.33603.86', 'fixed_display': '17.4.33603.86 (17.4.7)'},
  {'product': '2022', 'min_version': '17.5', 'fixed_version': '17.5.33530.505', 'fixed_display': '17.5.33530.505 (17.5.4)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
