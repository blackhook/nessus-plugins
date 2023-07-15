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
  script_id(175335);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2023-29338");
  script_xref(name:"IAVA", value:"2023-A-0238-S");

  script_name(english:"Security Update for Microsoft Visual Studio Code (May 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Visual Studio Code installed on the remote host is prior to 1.78.1. It is, 
therefore, affected by an information disclosure vulnerability. An unauthenticated, remote attacker 
can exploit this to disclose potentially sensitive information.

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version");
  script_set_attribute(attribute:"see_also", value:"https://code.visualstudio.com/updates/v1_78");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29338
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?128cba74");
  script_set_attribute(attribute:"solution", value:
"Upgrade to  Microsoft Visual Studio Code 1.78.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29338");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_code");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "microsoft_visual_studio_code_installed.nbin", "microsoft_visual_studio_code_win_user_installed.nbin", "microsoft_visual_studio_code_linux_installed.nbin", "macosx_microsoft_visual_studio_code_installed.nbin");
  script_require_ports("installed_sw/Microsoft Visual Studio Code", "installed_sw/Visual Studio Code");

  exit(0);
}

include('vcf.inc');

var os = get_kb_item_or_exit('Host/OS');
var app_info;

if (tolower(os) =~ 'windows')
{
  get_kb_item_or_exit('SMB/Registry/Enumerated');
  app_info = vcf::get_app_info(app:'Microsoft Visual Studio Code', win_local:TRUE);
}
else if (tolower(os) =~ 'linux|mac os')
{
  get_kb_item_or_exit('Host/local_checks_enabled');
  app_info = vcf::get_app_info(app:'Visual Studio Code');
}
else
{
  audit(AUDIT_OS_NOT,'affected');
}

var constraints = [
  { 'fixed_version' : '1.78.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
