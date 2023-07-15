#TRUSTED 4031a194150b221b5b6239f13157d91f4bfb64702df5c4c0b6c91663e490cf695158bd3b855c8418f67d04b8d4ef4b60163426e1c9a1e614ad99486749082361cef326eb60e1651be08b6ceb88dc3cef78c49528c4cc88ea904703c37238ac7ca07dfe77c93cc1128c8e691a08ca12ea646f1beed18027129a074c71642cc1b500b0dcfbcfe523dcee4599804a52fc496d1d90e41c2442908739055e181018001c880e7c821c4520ff5b980f33067b15dcc776f4be02731df166b7150cb59a407253ae4090d27a341cc00bc51fbd41830884338fb8450724b08c3e47d832d586b3bebf5096b5ee1e54ec3840af0f6abb2c4262696d6b29f22acf28d8abb46e1393f7ae3828e65950cf0b1aee5e8b5061dbf06c531fbe3376fc64a8ba3e32db463781a77a466ffa88c81404c9648bf9955ef75d7ad8d0dd5ee23ff1a147853471b381e5d793cbfc7bc19449fb99e4c2c3814ceb493c3eee056d7a86d8eb5446d7b9c6d182eeb82b761442079461bd7b79977cffa1bcc1c9c048fc80e5b5c867a440de85730ee79ae0ace2118bfc031268ab2ef6af65a4b00cbc69c320c379e1409277c0c47e24578e45bf88a5f998ecc4d600e820d67960c88397e54591c2db4259ac7b01e1f1b7f9ed32857e11d71927fdde15ee72fbf9dc42acf252af9e9205cf3a6eeab473dc1ab5b05fc137694ed3f4c1e5e31d6c1d92bca76eca43c8e836
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158584);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2022-20756");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz77905");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-dos-JLh9TxBp");
  script_xref(name:"IAVA", value:"2022-A-0100-S");

  script_name(english:"Cisco Identity Services Engine RADIUS Service DoS (cisco-sa-ise-dos-JLh9TxBp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a denial of service (DoS) vulnerability exists in Cisco Identity Services 
Engine due to improper handling of RADIUS requests. An unauthenticated, remote attacker can exploit this issue, by
sending crafted RADIUS requests, to cause the RADIUS service to stop responding resulting in authorization / 
authentication timeouts.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-dos-JLh9TxBp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21a817e6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz77905");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz77905");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20756");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}
include('ccf.inc');
include('cisco_ise_func.inc');

var app_name = 'Cisco Identity Services Engine Software';
var product_info = cisco::get_product_info(name:app_name);
var patches = split(product_info['patches'], sep:', ', keep:FALSE);
var largest_patch = get_largest_patch(patches:patches);
var vuln_ranges = [];
var required_patch = '';

if (  # 2.2P17 and later	
      (product_info['version'] =~ "^2\.2([^0-9]|$)" && ver_compare(ver:largest_patch, fix:'17', strict:FALSE) >= 0) ||
      # 2.4P12 and later	
      (product_info['version'] =~ "^2\.4([^0-9]|$)" && ver_compare(ver:largest_patch, fix:'12', strict:FALSE) >= 0) ||
      # 2.6P5 and later	
      (product_info['version'] =~ "^2\.6([^0-9]|$)" && ver_compare(ver:largest_patch, fix:'5', strict:FALSE) >= 0) 
    )
{
  vuln_ranges = [{'min_ver':'2.2', 'fix_ver': '2.6.0.156'}];
  required_patch = '11';
}
# 2.7P2 and later
else if (product_info['version'] =~ "^2\.7([^0-9]|$)" && ver_compare(ver:largest_patch, fix:'2', strict:FALSE) >= 0) 
{
  vuln_ranges = [{'min_ver':'2.7', 'fix_ver': '2.7.0.356'}];
  required_patch = '6';
}
else if (product_info['version'] =~ "^3\.0([^0-9]|$)")
{
  vuln_ranges = [{'min_ver':'3.0', 'fix_ver': '3.0.0.458'}];
  required_patch = '5';
}
else if (product_info['version'] =~ "^3\.1([^0-9]|$)")
{
  vuln_ranges = [{'min_ver':'3.1', 'fix_ver': '3.1.0.518'}];
  required_patch = '1';
} 
else
  audit(AUDIT_HOST_NOT, 'affected');

# Unable to check if the device is configured to use RADIUS
if (report_paranoia < 2) 
  audit(AUDIT_POTENTIAL_VULN, app_name, product_info.version);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz77905',
  'disable_caveat', TRUE,
  'fix'           , 'See Vendor Advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
