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
  script_id(161118);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2022-23267",
    "CVE-2022-24513",
    "CVE-2022-29117",
    "CVE-2022-29145"
  );
  script_xref(name:"IAVA", value:"2022-A-0198");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (May 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges. 
    (CVE-2022-24513)

  - Multiple denial of service (DoS) vulnerabilities. An unauthenticated, remote attacker can exploit this to
    cause a DoS condition. (CVE-2022-29117, CVE-2022-23267, CVE-2022-29145)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.1#17.1.7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b32ad05");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0#17010--visual-studio-2022-version-17010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?351dbfaf");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c0a9394");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9#16.9.21
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cffc348");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 16.9.21 for Visual Studio 2019
        - Update 16.11.14 for Visual Studio 2019
        - Update 17.0.10 for Visual Studio 2022
        - Update 17.1.7 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24513");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

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
  {'product': '2019', 'min_version': '16.9', 'fixed_version': '16.9.32428.249'},
  {'product': '2019', 'min_version': '16.11', 'fixed_version': '16.11.32428.217'},
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.32428.209'},
  {'product': '2022', 'min_version': '17.1', 'fixed_version': '17.1.32428.221'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_WARNING
);
