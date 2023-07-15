#TRUSTED 47677920cd92614657c51e059595f4fafdc769add95446ee99ac1e6627443330846dc6fb356b9a5bb616502fc7396a981cd29f9ef25ba7dbf7aa8b50e122eee97514fad5b65b32e7fb0000bd7b351d298c694403e2fe3758f3a00756705f2fdb56263607f3b6b195a87bc1da8d6814bf86ecf921c57b288372f47255fce4a0f7cdd010f207a08b6d82181e116ef74152e3a3315f689c6e4060a68a50cb32f01d1eef69555ad8327aa6d646cf76b8e167068c99b79a3db21e19ea7ef8162141d296ac56c5f5da8cdebf9602292937be96549ffc918ebce02834027eef00ec83d93cd930d12467df12ea4023b606b2c122a409049b279fcc6d43db63668c73753dfd59bf5492e6b8286d840bbc128852b6d59d5dda03db87f08c2bd2817209bcc389cbd5226dc3dee63c81428807fb42edd2a5ad1c07a98aa6ac368b12df916ae4f4dc38e06bed4f3486fe9b4bcd480864031f73d45fd6108c86bd119b0384e311c176fbe4b902bedd85131eb251535108e3175302f12cba07651d3a9e5bd56b64a760bd9cf8768dd31c10063ea09cc289c505eea1311701c49a62c67b267c10207e536c0caec641b6837275c6166d24ca4f2913cb61870824da4c26dd1ce67f2c15c01cdc866ab7538b2613e9d2f2da2f55c4a713b8f04de3511a6b2e5f775bd1135bc95bfceef2110a04a687d62e1aba2f7081f70e86f8f024e7748445d8fcc2
#TRUST-RSA-SHA256 112ee14133447bdb0dcd27f03678edefc115887b6e964096a8e353c2fbe8ab1535e3f397e82d7b4f5ee1d1f93d557227b807ca9fa04129beaa8d5d1e7e2c00a016ee52933d3862eb103e5cc1b46d19713197a0429abea78ad1a74c8da74dfebc3ff9f019671b4ca2cfd070aaa4416aeb6957b5180e3b7816852d18d898c077a10aa925fe33a0b68ccdc2ff091628fa26fbabd053c83d2ab0405f0624f01eaf86577cf3bd4be311ca02109a364b826d92d434ccbd57e25d9a9a2bdbf21dbc3f32325efb4fa8fe2736201012ae72cc9d42d4ac68935e1f1e4967f493920679d8584796965b54526ff8d1fd2e60c268ce42e32e31d26e23f1dcd199fdb1fca3690343441dcd6b8ac189740ea309ce4d2223b32d9461b0b43efd8490148fe6c81e9ff1b4f44e0103a7f2442bfdc591f9ebf988f97e1ddf570b512b947939d2335d8c9bf95a73fa616df5ca496beb40a58b5514e4046b262b01bf48e4dae59fa29788ea9bdb0632d07c9143dc03604e9de837210aeb8c7bc1e75b557e88c3b25d00f94b54191ee47abd668e4c9c17e8fa7d7604f34ce263792e005724ed826da7fba8c3adab30b25eb272eb64cbaed99f6038e0a90f584473b63d4c7865fca05602ba38f9327403e8043e50505bb976a7f04982dc23cab3d0b73e6d16a4a1e11bc7e00833afab209e06948b799989d30836440b3d1c8abcfe447f58ed9b5b61797a3f
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160889);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2022-20742");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz81480");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-ipsec-mitm-CKnLr4");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Adaptive Security Appliance Software IPsec IKEv2 VPN Information Disclosure (cisco-sa-asaftd-ipsec-mitm-CKnLr4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability due to an improper
implementation of Galois/Counter Mode (GCM) ciphers. An unauthenticated, remote attacker can, by intercepting
a sufficient number of encrypted messages from the affected device, use cryptanalytic techniques to break the
encryption.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ipsec-mitm-CKnLr4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bfd62ea");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz81480");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz81480");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20742");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(325);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

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

var model = product_info.model;

if (model =~ '9300')
{
  # Only some versions of the 9300 security module are vulnerable
  # and we don't have a way to differentiate
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
}
else if (model !~ "4(112|115|125|145)")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  {'min_ver': '9.12', 'fix_ver': '9.12.4.37'},
  {'min_ver': '9.13', 'fix_ver': '9.14.3.13'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.21'},
  {'min_ver': '9.16', 'fix_ver': '9.16.2.7'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['anyconnect_client_services'],
  WORKAROUND_CONFIG['ipsec_gcm'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz81480',
  'cmds'    , ['show running-config', 'show running-config crypto ipsec']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
