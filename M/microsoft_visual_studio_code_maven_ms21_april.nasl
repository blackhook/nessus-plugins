#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148472);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-28472");

  script_name(english:"Security Update for Microsoft Visual Studio Code Maven for Java Extension (April 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Code Maven for Java Extension is prior to version 0.29.0. It is, therefore, affected by 
a remote code execution vulnerability. By persuading a victim to open specially-crafted content, an attacker could
exploit this vulnerability to execute arbitrary code on the system with privileges of the victim.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-28472");
  # https://github.com/microsoft/vscode-maven/blob/master/CHANGELOG.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e67673ac");
  # https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-maven
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29c0fcc8");
  script_set_attribute(attribute:"solution", value:
"Update the Microsoft Visual Studio Code Maven for Java Extension to version 0.29.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28472");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_code");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_visual_studio_code_win_extensions_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visual Studio Code");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'vs-code::vscode-maven', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '0.29.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

