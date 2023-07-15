#TRUSTED 2477105d90e6c604a371f7d17b56ae5094419160db8e8e84d11cd25ff9bf39e431a656087f5d23a8df90d16bc7d9889bafb30b71d085718068bc55200510befbd5fa0fd5cf66f3bc41090666f63fa438d2ca937152be6d3741f436317a3d06da771dd2573c6e54df4075efc1272b526a1ede4fd50aefe707d2d28ed8435593f1c54070e2659863cc1e225049ea9fa29684b87baf816e857157033b67f31c36a8396947cbba32ad53dd34cf60af9eff65248b51580d75090dbe6ed750a4f4685db286bf068eddf010266a0e84bcc02567d422acaabfa106e6caead80b2ab589b7142b9ad7a1bda6c07ec97e976c926139b64b5482fb436baab2582e6babe7e01efbd3d5227c73dc04b771745fbf57d126f9bf7a2bc456b70327dee936e1bf14b6af858e766f865ef07afbdb885d872f72fd1030723aa9c91314e7cfe4d43163938975dd42983683ce6d507e93df04dbee4cdcf876cf2f520e604334cf23c7aaeae2fd84fbf9778baf56b623b15dbeb25fe7baefe55cff7c33d6a81dff0da5b591f5ce7691e1e10f8311a562c51a470cca7e2d09fbb131dbb9a0145edbce39112f4cf83d1e4130e33dcc5e54cf66105d08f2bb9a08ab39ab09fbccf1060ba7000d8dbe00492cb00963361dc419bda37b4ff0c859ed72e64be646ad65ca46bc6328442e89b19ab99e631bcd0154007d8187dbabcaaf6b01c11236587ebe474258ab
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141121);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2020-12820");
  script_xref(name:"IAVA", value:"2020-A-0440-S");

  script_name(english:"Fortinet FortiOS < 5.6.13 / 6.0 < 6.0.11 Buffer Overflow (FG-IR-20-083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 5.6.13, or 6.x prior to 6.0.11.

It is, therefore, affected by an buffer overflow in the FortiClient NAC daemon that could
allow a authenticated remote attacker to crash the FortiClient NAC daemon and theoritcally
execute remote code, although no successful proof of concepts currently exist for the RCE.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-20-083");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.13, 6.0.11, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12820");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('hostlevel_funcs.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  {'min_version': '0.0', 'fixed_version': '5.6.13' },
  {'min_version': '6.0', 'fixed_version': '6.0.11' }
];

workarounds = [
  {config_command:'full-configuration', config_value:'fortiheartbeat enable'},
  {config_command:'full-configuration', config_value:'endpoint-compliance enable'}
];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, workarounds:workarounds, not_equal:TRUE);
