#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157841);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/11");

  script_cve_id("CVE-2022-21986");
  script_xref(name:"IAVA", value:"2022-A-0064-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (February 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security update. It is, therefore, affected by a denial of service
(DoS) vulnerability. An unauthenticated, remote attacker can exploit this issue to cause the application to stop 
responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.0.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fa3027e");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?520aa622");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9#16.9.17
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f6edee8");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.7#16.7.25
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8ca19e7");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - Update 16.7.25 for Visual Studio 2019
  - Update 16.9.17 for Visual Studio 2019
  - Update 16.11.10 for Visual Studio 2019
  - Update 17.0.6 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21986");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_visual_studio_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::visual_studio::get_app_info();


var constraints = [
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.7.32125.265'},
  {'product': '2019', 'min_version': '16.8', 'fixed_version': '16.9.32126.311'},
  {'product': '2019', 'min_version': '16.10', 'fixed_version': '16.11.32126.315'},
  {'product': '2022', 'min_version': '17.0', 'fixed_version': '17.0.32126.317'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_WARNING
);
