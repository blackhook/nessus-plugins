#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174021);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2023-29017");

  script_name(english:"Node.js Module vm2 < 3.9.15 Sandbox Breakout");

  script_set_attribute(attribute:"synopsis", value:
"A module in the Node.js JavaScript run-time environment is affected by a sandbox breakout vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Node.js module vm2 installed on the remote host is prior to 3.9.15. It is, therefore affected by a
sandbox breakout vulnerability. Untrusted code can break out of the sandbox created by the affected vm2 module and
execute arbitrary code on the host system.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/patriksimek/vm2/issues/515");
  # https://github.com/patriksimek/vm2/security/advisories/GHSA-7jxr-cg7f-gpgv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ab9f9b6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vm2 version 3.9.15 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29017");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vm2_project:vm2");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_win_installed.nbin");
  script_require_keys("installed_sw/Node.js");
  script_require_ports("SMB/Node.js/Module/vm2");

  exit(0);
}

include('vcf_extras_nodejs.inc');

var app_info = vcf_extras::nodejs_modules::get_app_info(app:'vm2');

var constraints = [
  { 'fixed_version' : '3.9.15' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

