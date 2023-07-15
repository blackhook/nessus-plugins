#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(168736);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-41127");
  script_xref(name:"MSKB", value:"5021668");
  script_xref(name:"MSFT", value:"MS22-5021668");
  script_xref(name:"IAVA", value:"2022-A-0531-S");

  script_name(english:"Security Updates for Microsoft Dynamics NAV (Dec 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics NAV install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics NAV install is missing a security update. It is, therefore, affected by a 
remote code execution vulnerability.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  # https://support.microsoft.com/en-gb/topic/cumulative-update-59-for-microsoft-dynamics-nav-2018-build-49497-1c6f41c5-3c16-48e0-ae23-c3595f0d74fa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?487b3df0");
  # https://support.microsoft.com/en-us/topic/released-cumulative-updates-for-microsoft-dynamics-nav-2017-99f042ca-81ed-9fd5-2645-75fa9590dfd1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9de5099");
  script_set_attribute(attribute:"solution", value:
"The solution varies for different versions of Microsoft Dynamics NAV :

  - Dynamics NAV 2017: Install update (build 30712) or later
  - Dynamics NAV 2018: Install Cumulative Update 59 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41127");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:dynamics_nav");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_nav_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics NAV Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics NAV Server';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '10.0', 'fixed_version' : '10.0.30712.0' }, # 2017
  { 'min_version' : '11.0', 'fixed_version' : '11.0.49497.0' }  # 2018
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);