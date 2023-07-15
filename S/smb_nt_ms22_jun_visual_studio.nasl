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
  script_id(162317);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/16");

  script_cve_id("CVE-2022-24513", "CVE-2022-30184");
  script_xref(name:"IAVA", value:"2022-A-0243-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (June 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges. 
    (CVE-2022-24513)

  - An information disclosure vulnerability exists in Visual Studio. An unauthenticated, remote attacker can exploit 
    this to disclose potentially sensitive information. (CVE-2022-30184)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.2.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4dc578a2");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0#17.0.11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78cfb1be");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b4266e8");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9#16.9.22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9a8e5ce");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.49
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01c6c181");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 15.9.49 for Visual Studio 2017
        - Update 16.9.22 for Visual Studio 2019
        - Update 16.11.16 for Visual Studio 2019
        - Update 17.0.11 for Visual Studio 2022
        - Update 17.2.4 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24513");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  {'product': '2017', 'min_version': '15.9', 'fixed_version': '15.9.28307.2019'},
  {'product': '2019', 'min_version': '16.9', 'fixed_version': '16.9.32602.290'},
  {'product': '2019', 'min_version': '16.11', 'fixed_version': '16.11.32602.291'},
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.32602.201'},
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.32602.215'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_WARNING
);
