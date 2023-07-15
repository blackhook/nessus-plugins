#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159733);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/17");

  script_cve_id(
    "CVE-2021-43877",
    "CVE-2022-24513",
    "CVE-2022-24765",
    "CVE-2022-24767"
  );
  script_xref(name:"IAVA", value:"2022-A-0142-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (April 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges. 
    (CVE-2022-24513, CVE-2022-24765, CVE-2021-43877)

  - A DLL hijacking vulnerability. An authenticated attacker can exploit this to execute arbitrary code. 
    (CVE-2022-24767)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.1.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4430ad6b");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0#17.0.8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4713eca");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3db71ebc");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3080f2b9");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.7#16.7.27
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40f1eef5");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.46
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bf12eb3");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 15.9.46 for Visual Studio 2017
        - Update 16.7.27 for Visual Studio 2019
        - Update 16.9.19 for Visual Studio 2019
        - Update 16.11.12 for Visual Studio 2019
        - Update 17.0.8 for Visual Studio 2022
        - Update 17.1.4 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24767");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/14");

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
  {'product': '2017', 'min_version': '15.9', 'fixed_version': '15.9.28307.1919'},
  {'product': '2019', 'min_version': '16.7', 'fixed_version': '16.7.32407.390'},
  {'product': '2019', 'min_version': '16.9', 'fixed_version': '16.9.32407.336'},
  {'product': '2019', 'min_version': '16.11', 'fixed_version': '16.11.32407.337'},
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.32407.392'},
  {'product': '2022', 'min_version': '17.1', 'fixed_version': '17.1.32407.343'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_WARNING
);
