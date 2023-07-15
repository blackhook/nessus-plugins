#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156194);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id("CVE-2021-43877");
  script_xref(name:"IAVA", value:"2021-A-0580-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (December 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security update. It is, therefore, affected by the following
vulnerability:

  - An elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.
    (CVE-2021-43877)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.0.3.0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd31d474");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1e6931a");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9#16.9.15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9913a470");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.7#16.7.23
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?014d202d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - Update 16.7.23 for Visual Studio 2019
  - Update 16.9.15 for Visual Studio 2019
  - Update 16.11.8 for Visual Studio 2019
  - Update 17.0.3 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43877");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/20");

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

# Visual Studio build numbers and release dates
# https://docs.microsoft.com/en-us/visualstudio/install/visual-studio-build-numbers-and-release-dates?view=vs-2022&viewFallbackFrom=vs-2021

var constraints = [
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.7.32002.127'},
  {'product': '2019', 'min_version': '16.8', 'fixed_version': '16.9.32002.222'},
  {'product': '2019', 'min_version': '16.10', 'fixed_version': '16.11.32002.261'},
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.32002.185'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_WARNING
);
