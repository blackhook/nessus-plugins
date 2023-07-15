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
  script_id(167246);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id("CVE-2022-39253", "CVE-2022-41119");
  script_xref(name:"IAVA", value:"2022-A-0480-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (Nov 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. 
It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit 
    Heap Overflow vulnerbaility in Visual Studio to bypass authentication 
    and execute unauthorized arbitrary commands. (CVE-2022-41119)

  - An information disclosure vulnerability. Local clone optimization 
    dereferences symbolic links by default and may cause an exposure 
    of sensitive information to a malicious actor. (CVE-2022-39253)

    Note that Nessus has not tested for this issue but has instead relied 
    only on the application's self-reported version number.");
  # https://learn.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.51
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f159a580");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.21
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70d5c904");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0#17.0.16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1826d497");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2?source=recommendations#17.2.10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58508f72");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33e8b7fa");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 15.9.51 for Visual Studio 2017
        - Update 16.11.21 for Visual Studio 2019
        - Update 17.0.16 for Visual Studio 2022
        - Update 17.2.10 for Visual Studio 2022
        - Update 17.4 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41119");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/10");

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
  {'product': '2017', 'min_version': '15.9', 'fixed_version': '15.9.33027.88', 'fixed_display': '15.9.33027.88 (15.9.51)'},
  {'product': '2019', 'min_version': '16.11', 'fixed_version': '16.11.33027.164', 'fixed_display': '16.11.33027.164 (16.11.21)'},
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-history
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.33027.175', 'fixed_display': '17.0.33027.175 (17.0.16)'},
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.33027.314', 'fixed_display': '17.2.33027.314 (17.2.10)'},
  {'product': '2022', 'min_version': '17.3', 'fixed_version': '17.4.33103.184', 'fixed_display': '17.4.33103.184 (17.4)'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_WARNING
);
