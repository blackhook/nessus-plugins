#TRUSTED a2dedb06139d7775839462e7134dc786f2b370f7bd22292dbbb5ed9be6a019f154c9aafd28f7df2ebc5749e6da001cee5c3d9df306c95ce10a9fcf6a6a4c4a54a95274420946ff136bd46621365f1060d92fd061d142d245071d0e8eceeb36f110e44eddf8879e15f617e67c4ba24f828bcc542beb729de8a7369b3880e8f1e02419c8c73769ddb59dabad427d109ee1af694ade33f000ce76e146b9efc9dd16421848d28ff66cf570c53cbd2ec651afe4386f9f1bae3c07821e82ba6b5cf66a1738d3fffbe88d8179208f6adf731150b263a82b19108f8be00722ca11cbf45100a3fca365466a1f8e930c38f32bf1a538e342a8a5de997f8272aa1d96323262ff1e96d423f35a8f490fccd4ea41aa98e19190818122b46c5c6269a409848bd792a2d01001834594ec29b91487987bcd854da504d3675208d7fc29e185f06e8b2df378690b89a8a9766672c3e731b1b31d3d36c96038b8bf7669e29f4617d7d3788c702b5904fbbad4817d39dc3c23d60b3fde3425fd26e8f62ea2acb34b13ba892c3d32fbf5e76377a643f0dab466e0c35816cf340d2c449d1d79bf6677ecaafe4bec28c254cf2ff806f3721f5bd214a243ef13e723890cfe659f09291047a3eddb65a4f6b7c70d4d9d7c56ce81d71f22cf15ed343d35b91dfcd3954e7c07f31b14a369992dfc4d9ae78981cea898cb961e93805fe0ecff237255d841fe49ef
#TRUST-RSA-SHA256 84007ed59ce6d9690f1b8be8ea2c5d5721e1695d01e442d5e54e73b09093ffd84e497f5b8d63672a9e0b8eb1c98ab73eb005cbde5389dea88e057cd915afeb8707b5c9124cd616aa99cb47b8cf97b467b6dce89256c587d5559c4c726fdec62020c076ab4f4f48dc735cabd0351b9a73ef9366222d30b2d25e66bb3e765e82ec5a7eef7f1b389e54b4e3cf337de98e298b29eb93cb794983aa201d5f637416eb91bea1410a4c37b655115433f3af3d61c25e5b852ae99d1b84ec872ee381d1a1d13594d0f67adbcfcbed6476d6c4012e9c19973cff35880f417aaa567cd9dfc79ab443193ae6c58cbfe373ae0d1790e678b3f8227bf64fb6fc4ea2a857a2f9902661f5fa8f27c184aa284f3077cbc20f0b10896ee6a9a04768962409ef7d47e3f8da08d296433b0a3638206c8fc868ee97c5533d5416794c67a8ffdf38564c71977ad6765bdd3ace124713780ea9d24d6712808fae018f9b31c1abffae2ba0f012b7297f8bb485cc13d1cca2c5fbd9d010be3cacca86bd6a3a8daffdaeb02dca167ab84f461c861432215d9cf11c5ffe1bf6d0c5cdc5fb9e0753cb346100e7bfd6035ee2595bc4113dbb4fdbee4ae0915bce3b8b77f202564a5d5adbe8eea0aad72bc1fdac06390b87f30c22076500f7e2b34881a9465a58dab454a3d92958730c8b65188879a6a389508ffb32245daca488b97dd5f417dac5330ca21a16f796
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164087);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/02");

  script_cve_id("CVE-2022-20713");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa04262");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-webvpn-LOeKsNmO");
  script_xref(name:"IAVA", value:"2022-A-0329-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Clientless SSL VPN Client-Side Request Smuggling (cisco-sa-asa-webvpn-LOeKsNmO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Clientless SSL VPN (WebVPN) component of Cisco Adaptive Security Appliance (ASA) Software could
allow an unauthenticated, remote attacker to conduct browser-based attacks.

This vulnerability is due to improper validation of input that is passed to the Clientless SSL VPN component.
Successful exploitation of this vulnerability could allow attacks to conduct browser-based attacks, including
cross-site scripting attacks, against the target user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
 number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-webvpn-LOeKsNmO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?231c9463");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa04262");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa04262");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var version_list=make_list(
  '9.8.1',
  '9.8.1.5',
  '9.8.1.7',
  '9.8.2',
  '9.8.2.8',
  '9.8.2.14',
  '9.8.2.15',
  '9.8.2.17',
  '9.8.2.20',
  '9.8.2.24',
  '9.8.2.26',
  '9.8.2.28',
  '9.8.2.33',
  '9.8.2.35',
  '9.8.2.38',
  '9.8.3',
  '9.8.3.8',
  '9.8.3.11',
  '9.8.3.14',
  '9.8.3.16',
  '9.8.3.18',
  '9.8.3.21',
  '9.8.3.26',
  '9.8.3.29',
  '9.8.4',
  '9.12.1',
  '9.12.1.2',
  '9.12.1.3',
  '9.12.2',
  '9.12.2.4',
  '9.12.2.5',
  '9.12.2.9',
  '9.12.3',
  '9.12.3.2',
  '9.12.3.7',
  '9.12.4',
  '9.12.3.12',
  '9.12.3.9',
  '9.12.2.1',
  '9.12.4.2',
  '9.12.4.4',
  '9.12.4.7',
  '9.12.4.10',
  '9.12.4.13',
  '9.12.4.18',
  '9.12.4.24',
  '9.12.4.26',
  '9.12.4.29',
  '9.12.4.30',
  '9.12.4.35',
  '9.12.4.37',
  '9.12.4.38',
  '9.12.4.39',
  '9.12.4.40',
  '9.12.4.41',
  '9.12.4.47',
  '9.12.4.48',
  '9.12.4.50',
  '9.12.4.52',
  '9.12.4.54',
  '9.13.1',
  '9.13.1.2',
  '9.13.1.7',
  '9.13.1.10',
  '9.13.1.12',
  '9.13.1.13',
  '9.13.1.16',
  '9.13.1.19',
  '9.13.1.21',
  '9.14.1',
  '9.14.1.10',
  '9.14.1.15',
  '9.14.1.19',
  '9.14.1.30',
  '9.14.2',
  '9.14.2.4',
  '9.14.2.8',
  '9.14.2.13',
  '9.14.2.15',
  '9.14.3',
  '9.14.3.1',
  '9.14.3.9',
  '9.14.3.11',
  '9.14.3.13',
  '9.14.3.15',
  '9.14.3.18',
  '9.14.4',
  '9.15.1',
  '9.15.1.1',
  '9.15.1.7',
  '9.15.1.10',
  '9.15.1.15',
  '9.15.1.16',
  '9.15.1.17',
  '9.15.1.21',
  '9.16.1',
  '9.16.1.28',
  '9.16.2',
  '9.16.2.3',
  '9.16.2.7',
  '9.16.2.11',
  '9.16.2.13',
  '9.16.2.14',
  '9.16.3',
  '9.16.3.3',
  '9.16.3.14',
  '9.16.3.15',
  '9.16.3.19',
  '9.16.3.23',
  '9.16.4',
  '9.16.4.9',
  '9.17.1',
  '9.17.1.7',
  '9.17.1.9',
  '9.17.1.10',
  '9.17.1.11',
  '9.17.1.13',
  '9.17.1.15',
  '9.17.1.20',
  '9.18.1',
  '9.18.1.3',
  '9.18.2',
  '9.18.2.5',
  '9.18.2.7',
  '9.19.1'
);


var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ssl_vpn'],
  WORKAROUND_CONFIG['ssl_clientless'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa04262',
  'cmds'    , make_list('show running-config', 'show running-config all group-policy')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);

