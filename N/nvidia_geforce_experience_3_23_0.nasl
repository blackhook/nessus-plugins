#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151287);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/28");

  script_cve_id("CVE-2021-1073");
  script_xref(name:"IAVA", value:"2021-A-0297-S");

  script_name(english:"NVIDIA GeForce Experience < 3.23.0 Insecure Sessions");

  script_set_attribute(attribute:"synopsis", value:
"A GPU companion application installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"NVIDIA GeForce Experience, all versions prior to 3.23, contains a vulnerability where, if a user clicks on a
maliciously formatted link that opens the GeForce Experience login page in a new browser tab instead of the GeForce
Experience application and enters their login information, the malicious site can get access to the token of the user
login session. Such an attack may lead to these targeted users' data being accessed, altered, or lost.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5199");
  script_set_attribute(attribute:"solution", value:
"Update to NVIDIA GeForce Experience version 3.23.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1073");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:geforce_experience");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_geforce_experience_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/NVIDIA GeForce Experience");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'NVIDIA GeForce Experience', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '3.23.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
