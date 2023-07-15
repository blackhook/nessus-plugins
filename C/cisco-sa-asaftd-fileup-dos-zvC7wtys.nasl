#TRUSTED 6ff45c17f1a9784dd9fb6524c9fd7a83ea660aca93f85c66cb208d2bbbc5e6149ae804f8377aa98bf9292eb8e2cc58d494c7719364ce37da80f1a48ba50fb7763e658848881e834ff6cdcfe4676bc05fc9ab20f38cbf31a282553a24212d22f06727dc5c82823b13a799d2844db1f41553e9bdb81128f922dc24501caaffa4cc05add2a8bd1dba9a4de4c07ec8c1a309c882224b56bb8d70585b82f2e09a228d70f2c65761fe9b2a13fd2966e016eb115b7483cd9272860208121ce1e76aceb59c7058383ff5bcbce53004d1c74fb0512e4972cc6308d2d31004148acf988ff6f94e90a32d77490218d1bdacb92b80a6412ae9400c5733fdafaea9e42aa5c3b552998882f6d64ee80a03e7c4aca9536b2fb472380cc9725cbec0c34822e756923c26c4451ca1906ad6bc162c813d55283ee8b2da239ed05c1bd31b42f5187bf05aff0b4d256ef94f44a7b2f59e57655a20c70f1508602fc4190edd092910898724f8f6295d5cf704d98ca30cec80887a450635a201bdd113aaa5ed0e049d897f297e9c3588effdc2fc6f0524f8ee911f0fe979955721df526db0785f3e43d23fc0211703b573313afa149868af13c56266b56eb6e80cf8f46314f1b642df9cef435d80b69b93a3c7399822f34d14e8d53935daa55043e31577ae8b1eceb1fc25159c423daf232627d26be01d7a643d1bc2ac490a1e4b361e8966292a87b70ca5
#TRUST-RSA-SHA256 5b2e5e05671534a04f90c1c7996069e9f62829f90729218703b8be7629173796061bcb79a69f8d0960cbcb9c80315eb314316b16b8065a8582d072d4ba7a462361fc46815ee81e75113e0f67c2e812c8f891443c624fd26bc13ef475a7335832cd06c142cc2bd07ddfa64dc1a176fd3a4850f1a4e81e5016190d67f244725d7022a0dd50c4217e2e325d66a84356517b1dcd9a7f8c6be1a3842385de74dab6eafb2b01a9246c33ec890bbf51ae75ebf30a4138e689f8ffa81c9d8df24e3213a0e3c869ef3acd283464188fd3211f378837c138487a763bceb1607f1e818947034d980e9d505492c3f4194fb75cd439b01a8f8392efbbea3fa0d723d3f86a2dd8d03e9d4b00583640e7910be8d6ff981b31339a01971a6a77fce0d3e8a5bcd10306801ed96c82d736921649a1476486f08d46251c4e0457362ff678e1228642ffcbbeee2837af9ccadae7a66c1ed1a527f9f496ee19ce76c4f0a0468a51f32fd82833b50502bf195509012cc2cf1e8a886d2063a708305a7460de8c22c243910488572bccf467e4f167c320c2f1b5b78767e21b6d642675f2ea5518b558e50d4d98ef4d8e7de9e85acfcacaad1552fd0c820d0ed36143038212c73c23077a78fefee530dc4b72ce725ed4ef3c4f34fb17a2a9acf4b5790cde0e01699817868ab8e669df2966078821cd581e155c09cdc73a1edb11d28be2bf209bac7b1c41cc0b
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152673);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3436");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt60190");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-fileup-dos-zvC7wtys");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services File Upload DoS (cisco-sa-asaftd-fileup-dos-zvC7wtys)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance Software is affected by a vulnerability in
the web services interface that allows an unauthenticated, remote attacker to upload arbitrary-sized files to specific
folders on an affected device, which could lead to an unexpected device reload. The vulnerability exists because the
affected software does not efficiently handle the writing of large files to specific folders on the local file system.
An attacker could exploit this vulnerability by uploading files to those specific folders. A successful exploit could
allow the attacker to write a file that triggers a watchdog timeout, which would cause the device to unexpectedly
reload, causing a denial of service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-fileup-dos-zvC7wtys
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?565ae2af");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt60190");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt60190");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3436");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.6.4.45'},
  {'min_ver': '9.7', 'fix_ver': '9.8.4.25'},
  {'min_ver': '9.9', 'fix_ver': '9.9.2.80'},
  {'min_ver': '9.10', 'fix_ver': '9.10.1.44'},
  {'min_ver': '9.12', 'fix_ver': '9.12.4.2'},
  {'min_ver': '9.13', 'fix_ver': '9.13.1.12'},
  {'min_ver': '9.14', 'fix_ver': '9.14.1.15'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['anyconnect_client_services'], CISCO_WORKAROUNDS['ssl_vpn']);

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt60190',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
