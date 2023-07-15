#TRUSTED 27125b29a251b3c070c24e3a6c1257604d386137dabb3c5418a9fc0c478521b2f09efa2b297c1ec22a0790e9f4e70c5af399a0259e3f6567533d02d609923617bd5aa7a831b20df8f8d3e2c525795e25051cacf03ccca6118e94efa622411135e5624d65df861e5e82ef4f31a7cde50205973568d1f75eae0d13ae0887e1aa5182d196cd71d3b243828d148842560049c60816f51aa3840db17fc30c3f091c4d763fe52cb70dcb34fd437fd4e28d768675b9759bf6750001e35d0cb5d9850cbccd5e242fc3925a97ed5a56c57eaa98fa16ba176b7a0a4c5be75eb2f8005729cfe3fd7b185e2c0115c214342c6b92bd177a883f9efb4377817e4e2135039e0f9ed90bf48dff2d731ef40513dec143320210f35538365b4d2188511a366efa78defd5619046f848cf379220afd54922e800224b598c1ed111eae98f95a66d4e2c80f5a93a78d9fd67dc2946ec037f739091a9d6435882ab66f069aa0ca735c4f0f5b2734aae3d812160300a947934931dfb4b42f287a378fb391923d4310ce416bd8178832bb19639af6e62f01cbbfdf7c0d55fe229643a9f94c3289aa9a5b74ca6bca1c8b31dc43a14fd088a8f2884b2a9f966947170ab5732332ea98337dd4a4bd0c99fa78b95dca2d04a914a30f92a5a034b0d434d9b84c95fe6910f3bb8c7b9efc9aa61f17b7fe09765fd3ab4ff54945875b8833798de4e5e2f00ab57c79a8
#TRUST-RSA-SHA256 795261dd4aeb3be34970b48883ace1dafd6dfcf12c9b8f05217f7da21e463fd344a53987f337e0536faceecf4e7ed0083b83427d8dfa5139f49f5373e73aee855bf2fc8ae704dc9af5c9406d98e970d0916da0ea5b6780ac794930a25f666e6829cf563d73aab24b412446636321802ccaeec7f5b24962f4a81f3e6305d92a75cc12b0b10eefebf21ed796089cd114e23e54fd9265d7eedb5b67031237080fb52a07ec84c7f44d404d36ae1e85d402c7e1b523d2adc173757fc40e2d76f66f160854bd015c51474c4f5e1b5cbd8765256039b9f6cf6b5c0ab8e663e3efd45ef89ad4668950ee1137cc9d5f138b380b2ff134c5f89a1420995f3e9aff9331cfb2011c0fe763be14ea6fce20036842d9e5132d2943bf1982ee3c87680232fe2d3a27c70f742f0303b8930c8357ccd8ea03bc991c52818152cbf0af40244d12336042b6a37aa6567815fd520413f8489afb28aa83f1e2ae2af0690c60f4e18cf467bfefca377a9822770b87ccb373accdb9bddaca98ab34d48bdd660f81337aeef7ca275a35c219658a25aab2ff12fe32619fc08697fde8b2d849db2fd784ceab30999ad5452d9755ff41249791f997f8bc0c9f27593e94df38c02c2ce95575518f8ab2464a4a1eee0ccdaffbe33fa831ca2eb0af87dc0a2494aeb8c7816a1da3bfd09188a3f1642e3b4b5d840d45eaf8d4567a53baf20d89e4de1a8a9a5daa445b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148021);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/30");

  script_cve_id("CVE-2021-1361");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw89875");
  script_xref(name:"CISCO-SA", value:"cisco-sa-3000-9000-fileaction-QtLzDRy2");

  script_name(english:"Cisco NX-OS Software Unauthenticated Arbitrary File Actions Vulnerability (cisco-sa-3000-9000-fileaction-QtLzDRy2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-3000-9000-fileaction-QtLzDRy2)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software for Cisco Nexus 3000 Series Switches and Cisco Nexus 9000
Series Switches in standalone NX-OS mode are affected by a vulnerability in the implementation of an internal file
management service. An unauthenticated, remote attacker could exploit this vulnerability by sending crafted TCP packets
to an IP address that is configured on a local interface on TCP port 9075 in order to create, delete, or overwrite
arbitrary files, including sensitive files that are related to the device configuration. 

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-3000-9000-fileaction-QtLzDRy2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2770321c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74414");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw89875");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw89875");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1361");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(552);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl","cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
var smus = {};

if (('Nexus' >!< product_info.device || product_info.model !~ "^[39][0-9]{3}"))
audit(AUDIT_HOST_NOT, 'affected');

var vuln_versions = make_list(
  '9.3(5)',
  '9.3(5w)',
  '9.3(6)'
);

smus['9.3(5)'] = 'CSCvw89875-n9k_ALL-1.0.0';
smus['9.3(5w)'] = 'CSCvw89875-n9k_ALL-1.0.0';
smus['9.3(6)'] = 'CSCvw89875-n9k_ALL-1.0.0';

var reporting = make_array(
  'port'     , 0,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw89875',
  'severity' , SECURITY_HOLE
);

var workarounds = make_list(CISCO_WORKAROUNDS['show_sockets_connection_check_port']);
var workaround_params = {
  'vuln_string' : 'tcp LISTEN 0 32 * : 9075', 
  'patch_string' : 'tcp LISTEN 0 32 *%veobc:9075'
};

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions,
  smus:smus
);
