#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164551);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/30");

  script_cve_id("CVE-2022-2915");
  script_xref(name:"IAVA", value:"2022-A-0344");

  script_name(english:"SonicWall Secure Mobile Access (SMA) < 10.2.1.5-34sv Buffer Overflow (SNWLID-2022-0019)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is a SonicWall Secure Mobile Access (SMA) device with a version number < 10.2.1.5-34sv. It is, 
therefore, affected by a buffer overflow vulnerability that allows a remote authenticated attacker to cause Denial 
of Service (DoS) on the appliance or potentially lead to code execution.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2022-0019");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a SonicWall SMA version that is 10.2.1.6-37sv or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:sonicwall:firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_sma_web_detect.nbin");
  script_require_keys("installed_sw/SonicWall Secure Mobile Access", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');

var app_name = 'SonicWall Secure Mobile Access';

var app_info = vcf::combined_get_app_info(app:app_name);

var constraints = [
  {'min_version' : '0.0', 'fixed_version' : '10.2.1.5.35', 'fixed_display' : '10.2.1.6-37sv'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  require_paranoia:TRUE # Can't check for vulnerable models
);
