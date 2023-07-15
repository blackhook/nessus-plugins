#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153428);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-26434", "CVE-2021-36952");
  script_xref(name:"IAVA", value:"2021-A-0430-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (September 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security update. They are, therefore, affected by multiple
vulnerabilities:

  - A permission assignment vulnerability exists in Visual Studio after installing the Game development with C++
    and selecting the Unreal Engine Installer workload. The system is vulnerable to LPE during the installation 
    it creates a directory with write access to all users. (CVE-2021-26434)

  - A code execution vulnerability exists in Visual Studio due to incorrect memory handling. An unauthenticated, 
    local attacker can exploit this to bypass authentication and execute arbitrary commands. (CVE-2021-36952) 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1db01a4c");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9#16.9.11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c03ca82f");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.7#16.7.19
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae9fc5ee");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.4#16.4.26
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee4d9587");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.39
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e51fa707");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - Update 15.9.39 for Visual Studio 2017
  - Update 16.4.26 for Visual Studio 2019
  - Update 16.7.19 for Visual Studio 2019
  - Update 16.9.11 for Visual Studio 2019
  - Update 16.11.3 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26434");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-36952");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_visual_studio_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}
include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::visual_studio::get_app_info();

var constraints = [
  {'product': '2017', 'fixed_version': '15.9.28307.1684'},
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.4.31709.291'},
  {'product': '2019', 'min_version': '16.5', 'fixed_version': '16.7.31701.349'},
  {'product': '2019', 'min_version': '16.8', 'fixed_version': '16.9.31702.126'},
  {'product': '2019', 'min_version': '16.10', 'fixed_version': '16.11.31702.278'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_HOLE
);
