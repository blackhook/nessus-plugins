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
  script_id(171443);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id(
    "CVE-2023-21566",
    "CVE-2023-21567",
    "CVE-2023-21808",
    "CVE-2023-21815",
    "CVE-2023-23381"
  );
  script_xref(name:"IAVA", value:"2023-A-0088-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (Feb 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication
    and execute unauthorized arbitrary commands. (CVE-2023-21808, CVE-2023-21815, CVE-2023-23381)

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.
    (CVE-2023-21566)

  - A denial of service (DoS) vulnerability. An attacker can exploit this issue to cause the affected 
    component to deny system or application services. (CVE-2023-21567)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.4.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9391e916");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2#17.2.13
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?258c89f1");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0#17.0.19
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5fbfb7de");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e3f2fa2");
  # https://learn.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.52
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d28f347e");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 15.9.52 for Visual Studio 2017
        - Update 16.11.24 for Visual Studio 2019
        - Update 17.0.19 for Visual Studio 2022
        - Update 17.2.13 for Visual Studio 2022
        - Update 17.4.5 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21808");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-23381");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/14");

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
  {'product': '2017', 'min_version': '15.9', 'fixed_version': '15.9.33403.129', 'fixed_display': '15.9.33403.129 (15.9.52)'},
  {'product': '2019', 'min_version': '16.11', 'fixed_version': '16.11.33328.57', 'fixed_display': '16.11.33328.57 (16.11.24)'},
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.33402.176', 'fixed_display': '17.0.33402.176 (17.0.19)'},
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.33402.178', 'fixed_display': '17.2.33402.178 (17.2.13)'},
  {'product': '2022', 'min_version': '17.4', 'fixed_version': '17.4.33403.182', 'fixed_display': '17.4.33403.182 (17.4.5)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
