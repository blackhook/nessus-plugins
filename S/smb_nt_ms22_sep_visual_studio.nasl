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
  script_id(165107);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/18");

  script_cve_id("CVE-2022-38013");
  script_xref(name:"IAVA", value:"2022-A-0370-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (Sep 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Visual Studio. An authenticated, remote attacker can exploit this
issue, to cause the system to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3080f2b9");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da7114cb");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd72ca6d");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?234d80c0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - Update 16.9.32901.84 for Visual Studio 2019
        - Update 16.11.32901.82 for Visual Studio 2019
        - Update 17.0.32901.226 for Visual Studio 2022
        - Update 17.2.32901.213 for Visual Studio 2022
        - Update 17.3.32901.215 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38013");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

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
  {'product': '2019', 'min_version': '16.9', 'fixed_version': '16.9.32901.84'},
  {'product': '2019', 'min_version': '16.11', 'fixed_version': '16.11.32901.82'},
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.32901.226'},
  {'product': '2022', 'min_version': '17.2', 'fixed_version': '17.2.32901.213'},
  {'product': '2022', 'min_version': '17.3', 'fixed_version': '17.3.32901.215'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_WARNING
);
