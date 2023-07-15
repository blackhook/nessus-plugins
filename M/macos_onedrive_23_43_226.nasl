#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172605);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/17");

  script_cve_id("CVE-2023-24930");
  script_xref(name:"IAVA", value:"2023-A-0141");

  script_name(english:"Microsoft OneDrive for MacOS < 23.043.0226 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote macOS /Mac OS X host is affected by a privilege escalation vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft OneDrive for MacOS on the remote macOS / Mac OS X host is prior to 23.043.0226. It is,
therefore affected by an escalation of privilege vulnerability. An authenticated, local attacker can elevate to
SYSTEM privileges.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24930");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft OneDrive for MacOS version 23.043.0226 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24930");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onedrive");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_onedrive_installed.nbin");
  script_require_keys("installed_sw/OneDrive", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/MacOSX/Version');
get_kb_item_or_exit('Host/local_checks_enabled');

var app_info = vcf::get_app_info(app:'OneDrive');

var constraints = [
  { 'fixed_version' : '23.043.0226' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
