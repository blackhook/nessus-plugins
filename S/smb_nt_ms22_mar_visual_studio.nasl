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
  script_id(158715);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/18");

  script_cve_id("CVE-2020-8927", "CVE-2022-24464", "CVE-2022-24512");
  script_xref(name:"IAVA", value:"2022-A-0105-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (March 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2022-24464)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2020-8927,
    CVE-2022-24512)

    Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
    number.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.7#16.7.26
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96707195");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9#16.18
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb3a560d");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b54be023");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.1.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dae83367");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 16.7.26 for Visual Studio 2019
        - Update 16.9.18 for Visual Studio 2019
        - Update 16.11.11 for Visual Studio 2019
        - Update 17.1.1 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24512");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8927");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::visual_studio::get_app_info();

var constraints = [
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.1.32228.430'},
  {'product': '2019', 'min_version': '16.10', 'fixed_version': '16.11.32228.343'},
  {'product': '2019', 'min_version': '16.8', 'fixed_version': '16.9.32228.547'},
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.7.32228.349'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_WARNING
);
