#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147727);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-27060");

  script_name(english:"Security Update for Microsoft Visual Studio Code (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An arbitrary code execution vulnerability exists in Microsoft Visual Studio Code. An unauthenticated, local attacker can
exploit this by persuading a victim to open specially-crafted content which could exploit this vulnerability to execute
arbitrary code on the system with privileges of the victim.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-27060
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36f42535");
  script_set_attribute(attribute:"see_also", value:"https://code.visualstudio.com/updates/v1_54");
  script_set_attribute(attribute:"solution", value:
"Upgrade Visual Studio Code to 1.54.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27060");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_code");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "microsoft_visual_studio_code_installed.nbin", "microsoft_visual_studio_code_win_user_installed.nbin", "microsoft_visual_studio_code_linux_installed.nbin", "macosx_microsoft_visual_studio_code_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visual Studio Code", "Host/OS");

  exit(0);
}

include('vcf.inc');

os = get_kb_item_or_exit("Host/OS");
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

constraints = [
  { 'min_version':'0.0', 'fixed_version' : '1.54.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);