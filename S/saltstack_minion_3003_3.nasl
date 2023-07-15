#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158554);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/01");

  script_cve_id("CVE-2021-21996");
  script_xref(name:"IAVA", value:"2021-A-0524-S");

  script_name(english:"SaltStack Minion 3000.x < 3001.8 / 3002.x < 3002.7 / 3003.x < 3003.3 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The version of SaltStack Minion running on the remote server is affected by remote a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of SaltStack has a Minion component installed on the remote
server and is affected by a remote code execution vulnerability. A remote, unauthorized attacker can trigger this 
exposure with a carefully crafted payload to gain full file system access as root by injecting malicious code into the 
full path string.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version");
  # https://saltproject.io/security_announcements/salt-security-advisory-2021-sep-02/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ee2473e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SaltStack version referenced in the vendor security advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21996");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:saltstack:salt");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("saltstack_salt_minion_linux_installed.nbin");
  script_require_keys("installed_sw/SaltStack Salt Minion");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'SaltStack Salt Minion');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'fixed_version' : '3001.8'},
  { 'min_version' : '3002.0', 'fixed_version' : '3002.7' },
  { 'min_version' : '3003.0', 'fixed_version' : '3003.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);