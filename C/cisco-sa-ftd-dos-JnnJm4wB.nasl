#TRUSTED 677dc7ce17cd2e5103e6811e7b3b76206a8ebc7b9a694e6962b910d906212085ecf94dca5679035d206182d9a2812093f2744f6049a4fbc57eec8907ebeda3d5989fda6d16229898734d92115ca75e720ebc08ff1f71e1f656e2afa00bfafab0b8656316ca7d3111a228bc7f51e3a725e208823116a143a296a8ab8deca6829a18260c5bc98da83839eba5fdba8f7b632832a4dee691220b95a48065d840e6b000ef45431619c95562f40eab22d3245ee1c6250042eab344e244a7033441817a7214de02d65880bbe989afbbd734889ae60b5d93b3e9d919427c69755e3422c20feba1e5438487f02313e9ceb743019d4a6725ce219f01f1971891afbb86d143c5ecbd02fb78a5c28ee130893c11ca453d8dc00e0318a240eb82c358d9f4d4a4b5fc4116ebd31f7a6ba9d22276182753290375efff51a43eccc6c59316bc5ff39e6202b66937dccc2097c4ed06379ae04745172f49d6bf91826df82d4fb18663ea1f6ef7dda68e74a23386e6539d176bbc63ae91a0e048d11a4de347dcf702fb8080ae2c96097976b745a5ca50955b5fcb9a6883a53be515655e03d97f0e9d0f23d19a542055d37f2b8e60bbb98459d2860725f7c0b299a41a5c2b13b4208bc5ea81661134f77cf42c003266f888816d5c847de246380bff788c600523868806b1088e4baaa8d190c38aefeef48cd442b0211051d4145bf1616c69d242c8aa7b
#TRUST-RSA-SHA256 17f5faef78d1a7bb617f6b5366786be58e7754de19e295a8bfefb235c6c933195b9117ca8bc2a160d096edac53d24e99ce998a4c68a7a137108346ea38a05c54d2f6a2ceeec0536663a8dd274d9e921eb0511f2779ecfb216d4ae7e6b4762af10d65665d2ae0c10f72b34eb2333517ff386a74c38b20bffccb9e412c60e6b32e89f02a93b5b490d40350446e8dd1737ac4ad2ea72605b8f7bd2c95e10076b8175f32e4f8cf6f8a1d7adb80814ec64a1b6488b32204ada4165c2581c72adac9a72d8e6ad1b3e2b45b68e5cde92de51ae61ddb15cfe9208e5d605f429ca0a68c417da2bdc4c89661bc525a71b2cd0295fb6963bea510f632f771b166a4d85714a87456d003ae47442674842882666c00b066c12c70c3689263eb6ec9cfc6433c600ffca0e11ed5632c228c6eded4d74865795ecfc3d9c6b8e17be11a7c5b22c7964e01fe0c11ce8d826638fc2205d88495f82337f840886c9f1c2d8748c15608d744db6381212128186e46e0a9b04d9962836b672af34f4decb509400ca24347b3e42eace576984f61ad941360171df4fbf4fd89f404a6965f794ee15a980bcde31c5a67b31f0ceed923a2b3ff5ac7925e2fb2ad9f75857dbe7342f72d2ba7a0f54763e5d91523ec707cd9d0d5d45c4b6858075b885045d70234cb6e2612df86957de90bdfd144605709cdc75cae95144a31545d2029de49c9e269ee61855e7b25
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161043);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2022-20757");
  script_xref(name:"IAVA", value:"2022-A-0184-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa14485");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-dos-JnnJm4wB");

  script_name(english:"Cisco Firepower Threat Defense Software DoS (cisco-sa-ftd-dos-JnnJm4wB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the connection handling function in Cisco Firepower Threat Defense (FTD) Software could allow an 
unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability 
is due to improper traffic handling when platform limits are reached. An attacker could exploit this vulnerability by 
sending a high rate of UDP traffic through an affected device. A successful exploit could allow the attacker to cause 
all new, incoming connections to be dropped, resulting in a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-dos-JnnJm4wB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e5315e4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa14485");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20757");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(770);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

# adding paranoid wasn't able to check the configuration for Snort2 or Snort3
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var firepower_hotfixes;
var extra;
var fix;

if (product_info.version =~ "6\.7\.0")
{
  if (!get_kb_item("Host/Cisco/FTD_CLI/1/expert"))
  {
    if (report_paranoia < 2)
      audit(AUDIT_PARANOID);
    extra = 'Note that Nessus was unable to check for hotfixes';
  }
  else
    firepower_hotfixes = {'6.7.0': {'hotfix': 'Hotfix_AA-6.7.0.4-2', 'ver_compare': FALSE}};
  fix = 'See vendor advisory';
}

var vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '6.4.0.15'},
  {'min_ver' : '6.5',  'fix_ver' : '6.6.5.2'},
  {'min_ver' : '6.7',  'fix_ver' : '6.7.0.4'},
  {'min_ver' : '7.0',  'fix_ver' : '7.0.2'},
  {'min_ver' : '7.1',  'fix_ver' : '7.1.0.1'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCwa14485',
  'fix'      , fix,
  'extra'    , extra
);

cisco::check_and_report(
  product_info      :product_info, 
  reporting         :reporting, 
  vuln_ranges       :vuln_ranges,
  firepower_hotfixes:firepower_hotfixes
);
