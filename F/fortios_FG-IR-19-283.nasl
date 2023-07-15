#TRUSTED 9a23841f867df62bdf183078d2e30d25ccd15ff6fe42c03155df4caf115d6c69cf21029c65c2e1297158601bcb80232a8994816e715228a1787029f52cde8a7cb9d79a65c9e941e5df95df431a1f66305314c0cf6f9a7dcd729fb6250e9c09c9ba0f1fe04c62191c1143efe2a8d15d19ae7e0ba14ce3fb25d7c469057306524ec52e8ffade9fcfaef44562fe86c3dfd82c654bc19109750e08977bd69f78ca65edf88996fd21a18f8ebd7cf69f03ff7cfabe4371651e8295678598743d2b54aa3ba56cca096d144da73c19c987523801475204194fbec2d1489c8a6093c482912e75d84bcf5bd0a1bd22353b9eef74cbe27c62ffb52cdfd39f10255546a3243078b5410d500e12c6eeb6506e3c2bded260515c74894cd395517336bdd3401d564e17c35456d8e01a57068448bb1250ca376e451c40bad9b4833bd84db9abff41629bd933fc2d2226c13a7ef8e049c45fc56a15d01f6ca0e30d541b4fb2dce8e5112d169c9788964c2e59c70649eb4185745d9dfe527c7a1b119567c6ca7dd49c1a586c9e338c1c2ee9e4f3f0ccb1066cfc857ecd0fc1ee402066e78f617fbcd9153e0859095ba4e371432cf1ba66ba48a35be5cf75f2dc097c119b97e64e35a535b8abb38e6eac436c5f8592407b07304505fc2776d95f14c562e7fea094aec447f66c1e7cdb94705dcba5928c19c46af921e9a6542f97d7038cefa585b7e496
#TRUST-RSA-SHA256 541a8edfa6b7f4fd0780591590e9e7e74b946807362a4126433b3aee4218dfeda8d822435248a740a107b722e85059fac77bccd44a3571d9322d80575177c220e221be1f2511be83481ac35a6a3e65a790adea83ac3b2cf8ce0a476ac85f5acff1f259ea3a01dac9dc72957cae9c8b94aac89e9e738e1a1a743a8d98945ea280392fd7058e9e6cfdb6820e3894b3880af0d649ecb3a5cc7428eaaa5a0d7090ae6455a444a0fdac38059aeeac03efc6b0d7c3caefa43a8cd64dfd708e7c6ca6fa3fcfe68da1b9cbf6ee956ee1cd16225c9ef9a094864c967dec416267f65c671a94ff7128373d2c85adf43fd00afbc3acf0ba80b4fe70de979c31aaa932fc1923dfed90ee8a6c4224a7e8605fd8fd5cc80b72433bbdf9207a0a63254c7aaced060cf9d613d352fe14cf42fb9ce8f3d24e11d62046d25ecf8c401276da32f1d875342f089bb3651430ca5d82b98d93cefb786810b1df3261a4212bf9ff1278c6e6c00d00ba0a79693b304c957782524866793f0c78d25eb9903e0d8a83e1262342f52cd7fa44375c50b1cb72b2f22320220052c637e81f0537cc0a473960503e45bf0db22364301fd9cd2377141b0aebba45f2dcd3c449e1db2e236633449133bdbf2d93186284ac9e952c29b752b7dcd981ccae994896ddb6d1a925f9ce9d679b61f9f4734382268486aa4d45ac521aceaecca379255f7a9e17ca7f4a7a9f03a1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141122);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-12812");
  script_xref(name:"IAVA", value:"2020-A-0440-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2021-0020");

  script_name(english:"Fortinet FortiOS < 6.0.10 / 6.2.x < 6.2.4 / 6.4.x < 6.4.1 Improper Authentication (FG-IR-19-283)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an improper authentication vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 6.0.10, 6.2.x prior to 6.2.4, or 6.4.x prior to 6.4.1. It is,
therefore, affected by an improper authentication vulnerability due to an issue with the 'username-case-sensitivity' CLI
attribute for the SSL VPN. An unauthenticated, remote attacker can exploit this, by changing the case of the username,
to log in without being prompted for FortiToken 2FA.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-19-283");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 6.0.10, 6.2.4, 6.4.1 or later, or apply the workaround from the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12812");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/24");
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
  {'min_version': '0.0', 'fixed_version': '6.0.10' },
  {'min_version': '6.2', 'fixed_version': '6.2.4' },
  {'min_version': '6.4', 'fixed_version': '6.4.1' }
];

report =
  '\n  FortiOS is currently running a vulnerable configuration,'
  +'\n  Based on it\'s two factor authentication, which can be bypassed.'
  +'\n  via a flaw in the case sensitivity of usernames. Consider setting'
  +'\n  username-case-sensitivity to disable or other appropriate steps'
  +'\n  to prevent the FG-IR-19-283 vulnerability.'
  +'\n'
  +'\n  This issue can be found in the following configuration locations:'
  +'\n  user local | user peer | system admin.'
  +'\n'
  +'\n  Tenable does not print the user entry here for security & privacy reasons.';

var check_config =
{
config_paranoid : TRUE
};

vuln_settings = [ # Not_equal flag below ensure it only triggers if it can't find any of these three.
  {config_command:'full-configuration user local', config_value:"set type password"},                 # So if it's not type password
  {config_command:'full-configuration user local', config_value:"set two-factor disable"},            # Or it's not two factor ID
  {config_command:'full-configuration user local', config_value:"username-case-sensitivity disable"}, # OR If case sensativity is off, it's immune.
  {config_command:'full-configuration user local', config_value:"config user local[\r\n\s]*end"} # OR If case sensativity is off, it's immune.
];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, report:report, vuln_settings:vuln_settings, all_required:TRUE, not_equal:TRUE, regex:TRUE, config_optional:TRUE, show_check:'config', check_config: check_config);
