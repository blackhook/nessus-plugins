#TRUSTED 76d1ac799487360e60c4c09bac8233374b4316dccf441b0649d8460a71f3eaa4976a4610719dce604a1e133043b1bf3505b7d6ac988754eb22171ae220f67b987b229d68babcf93d0ce8145c0af33e6d53b8221d946ff87f60eb897c69b458e16cc673d9b57fe5d7535b3b779bda8162b313d3e7f4195c50255bc5bcdc4dae59ef1b49dc540f07bc3b8494afbf94de2752922a64417004e1a9a91805745d413505020326b3548ab73b3186de1af20a9cdc379a856265763b14864cc08ecf2c7310d23e1a55d268f76e1310ae5ed79c4a866340745cf31a67c797fa4f914d9b69e7af25e221f92426b5253800d34bf1b66ff1394689c674424e9ef7e3de50768a43e9fc0fd5f1d808d7bc9c18547726b2a46d4e6fdebe5eef20689a7e3ab7030fc6c979ce02062f7849cbeb762c8f9192799421afb2896e520b95e115ca979881ab29590d1fa827796bb6838a4651647f7542492346f061950261898f9bb003f9d12cbfe79b595c56cea893cf8a2cccf6ace94f6a405980031713a7f03f25b4f6098fd93e814ed45bc036bacd1cb56ad9c96a7f44ac78dcb8406854698349716dfa20443f5a07dd725d66c72b7d340b752a58bb302577f1b17f4e30eb7962a68505b2346f0943482d85a60de8862f455eaef657d265546be56c552a64063b44bb380452b383e71ad20979e2d54f218e163fed132925d6432977e831d53fbc4f4c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141567);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2020-12819");
  script_xref(name:"IAVA", value:"2020-A-0440-S");

  script_name(english:"Fortinet FortiOS < 5.6.13 / 6.0 < 6.0.11 / 6.1 < 6.2.5 / 6.3 < 6.4.2 Heap Buffer overflow (FG-IR-20-082)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 5.6.13, 6.0 prior to 6.0.11,
 6.1 prior to 6.2.5, or 6.3 prior to 6.4.2.

It is, therefore, affected by a buffer overflow in the Link Control Protocol that could
allow an authenticated remote attacker to crash the SSL VPN daemon and could be used to 
execute remote code.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-20-082");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.13, 6.0.11, 6.2.5, 6.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12819");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin", "ssh_get_info.nasl");
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
  {'min_version': '6.0', 'fixed_version': '6.0.11' },
  {'min_version': '6.1', 'fixed_version': '6.2.5' },
  {'min_version': '6.3', 'fixed_version': '6.4.2' }
];

workarounds = [{config_command:'full-configuration', config_value:"set tunnel-mode ((?!disable).)*$"}];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, workarounds:workarounds, regex:TRUE, not_equal:TRUE);