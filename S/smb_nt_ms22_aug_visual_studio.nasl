##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(164090);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id(
    "CVE-2022-35777",
    "CVE-2022-35825",
    "CVE-2022-35826",
    "CVE-2022-35827"
  );
  script_xref(name:"IAVA", value:"2022-A-0315-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (August 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - Fbx File parser Heap overflow Vulnerability. (CVE-2022-35777, CVE-2022-35826)

  - Fbx File parser OOBW Vulnerability. (CVE-2022-35825, CVE-2022-35827)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes#1730--visual-studio-2022-version-173
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90285035");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0#17.0.13
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f77456f3");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.18
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?448dfcf5");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9#16.9.24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf0c0841");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.50
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?116287fa");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 15.9.48 for Visual Studio 2017
        - Update 16.9.24 for Visual Studio 2019
        - Update 16.11.18 for Visual Studio 2019
        - Update 17.0.13 for Visual Studio 2022
        - Update 17.3.0 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35827");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/12");

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
  # Had to download file and check fileversion to get the build version
  {'product': '2017', 'min_version': '15.9', 'fixed_version': '15.9.28307.2094'},
  # https://docs.microsoft.com/en-us/visualstudio/install/visual-studio-build-numbers-and-release-dates?view=vs-2019&preserve-view=true
  {'product': '2019', 'min_version': '16.9', 'fixed_version': '16.9.32802.399'}, 
  {'product': '2019', 'min_version': '16.11', 'fixed_version': '16.11.32802.440'}, 
  # https://docs.microsoft.com/en-us/visualstudio/install/visual-studio-build-numbers-and-release-dates?view=vs-2022
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.32802.463'}, 
  {'product': '2022', 'min_version': '17.3', 'fixed_version': '17.3.32804.467'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_HOLE
);
