#TRUSTED 29e8fdbbd412b308c069040b41b6a61663495317b0cf5cda41f9cc5fcdc26f844df745007db1d83559495793b0f5d825e98f3907c0040cc7daa26392d397835129eb07cb0f3370610bedd1e3a4467fe81fd41d9af7e5df4c9fb7a92e89be0f4232bedd42f80ccc689e1601ec1c47849e49e12cc88141982fa7a2bb446db53ffe282d0a44a76d7faba68ba6cd47666999e971316e54dd757f961b444198e675ca34220162f129a26c2a28360546a789f65cc97d58e03502226dda7c6c0a37793bd46a3d9fe5fb2400dbf917157e91d807e49214dc67325b7b1b565fd85b9d190bf045f5465357582489c85264e4ab738f11d39900fdcf6268eef7972c4eb34c157e5582f9b1b97b91addcff8ec0ba8db91833451d44d2691302334b6ffa34d07f1e428dc1bb2d9920f484e075be658a169be554edc0327084e2b9bf29ae1a1952b22339eff5d47253dca41afe93c7aef4fdaed28a05096ef7ae811be00e5c5ba5ef438f157064a632906d926972deed1c1223f198e4d9199e34e464b51accee3a9b6dd0da59df1121e949e99e010fd9efb3b803e17756ecf68d9925953faead976b2b7eccbd71846c76c1d4a94180a6d138fef64c0b4297f60d73e25c396bedd207a20d8bc37ec3edb691f028d7929cfa979cffb56f1406cabaee738c61e7746a91aa2035cb897f9500f0003c3e8b191bdcab89c61fbbbe8f2395287b4e632bd0
#TRUST-RSA-SHA256 1442cb8ac64dd12218707ddbeae830fb99db57a2a07e1dc5f292e5ca451ab8c4ed439d2970596499af7cfcd4d33fa802712a9b908a83ecc5ac91a26921789fbb93a773f46d343afc0f3c8418be9e55634e581896e18091bfbaeffcb514c07a9a19a90bfe1c5337b76e1b5a9ea768e0ad3b0bfb4b80c1e847f630b8c65c0f9bdf25cf678c01fcf56633974b02e7bf3d819385306914e1006f366f37c2e2e11b531ba256c00ad153cc4814cb115ced7c964523398f4126abdbe7d16d94fb863e66986e64d0bcb804d5bc026dc9c303efa4753ab5f569084a2a7d1dd89706ee0473022a3c3cfdc11b547c03794e9052431c4b060daecafbcb154adde045cf599c402dacef4e59d7adb88be94338a16b6ec19109482446fff1a4582360cb8a6e637cac4469037d3d20c045fc6f35990738c329fa8d24aeead707d3a177a89469ff1c14a17d679f18312c8f75cc660d2ced25bbf874269ae280c48e7fbcc58f476386d7be4cfbe3b5b7c3412078c89e18062ae94c43c7494b5500b2669a738727189453a735de5a82a2b0be198cf0b3f51933e13fbb3604089dac3abca675b1648fc4dabdef67cae321b60c36438dd80008c6fa4f421cf06521ac6e069e4bf39dd81bbcb9b6c4b00035ce335c81ac22db1324edb74a39e0d7e593071493fa028796c5281a80bd48fa6963e516ccb60f1450cbdd9ec27c586702f6ee3014570b96fbe7
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169452);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/03");

  script_cve_id("CVE-2021-1624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx37176");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx75321");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ratenat-pYVLA7wM");
  script_xref(name:"IAVA", value:"2021-A-0441");

  script_name(english:"Cisco IOS XE Software Rate Limiting Network Address Translation DoS (cisco-sa-ratenat-pYVLA7wM) Unpatched Commands");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Rate Limiting Network Address Translation (NAT) feature of Cisco IOS XE Software
  could allow an unauthenticated, remote attacker to cause high CPU utilization in the Cisco QuantumFlow
  Processor of an affected device, resulting in a denial of service (DoS) condition. This vulnerability is due
  to mishandling of the rate limiting feature within the QuantumFlow Processor. An attacker could exploit this
  vulnerability by sending large amounts of traffic that would be subject to NAT and rate limiting through an
  affected device. A successful exploit could allow the attacker to cause the QuantumFlow Processor
  utilization to reach 100 percent on the affected device, resulting in a DoS condition. (CVE-2021-1624)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ratenat-pYVLA7wM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82b10ce9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx37176");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx75321");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx37176");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# paranoid because we're not checking versions
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# if the vuln sub-cmd config is found then the host is vulnerable, but no software updates/fixes are available
var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['iosxe_max-entries_unpatched'];

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '9999.9999'}  # not really checking versions
];

var reporting = make_array(
  'port'      , product_info['port'],
  'severity'  , SECURITY_WARNING,
  # bug id for this advisory plus the bug id for the unpatched commands
  'bug_id'    , 'CSCvx37176, CSCvx75321',
  'version'   , product_info['version'],
  'cmds'      , make_list('show running-config'),
  'fix'       , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
