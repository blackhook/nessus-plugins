#TRUSTED 74a2d53bbaee3dd2d32582114e24a0efcca44e06926714ae5f79b223a5d8f9535f11a2078e27aa5a94698b63fbf33457f803f5a9920fbdba890d92add00a343a142c3a35389eac30d4e638aed358af9abf93727d79f141fdb1d62b4be4f49236b772c0f9b6cf36ddb7ab130e95b3d29687ecc16778998a9e8f399c4f0987a73d79ab7b1cc8e2c4dc3dda5cdee252ba9cc88dfd4e1e026570874e649088603449dcd56f6c9bb646c995e9cea21499776e8add4d966bbfd7092e1c6d480b2f99353ee21cfe48eb13b9b3645bdc83c7d088b6f8f636b9253e6bad9caaa5f3fb36b13dc3ef3a568578b130f88be65750bdce86f67fc07a6e6be08b838e43240bce9da63d97106355367d5e2e0652d40e3f19e81f35beb27c00112badd3d32d54c87a7ae9effce036fe6a75574471aae7c5df33a0b617cc8a0fe1133e2a836cc6395d778c62a263f8a1ab4357e457548fa5dd309dafd9a47596ed5c9a1fb9fa585abfb6e089dd393437b8a7087e321a96c0c165340b7e9812e8100c51d6ca6fbf4daf009bfef5c3419b86ffeb7aaee100e8d25d7d1e64383e3e9f7bcf5d161a63159353b990cfe692da4f96ee080a7c1212c7426450d3a180ebc641b2b9c8473aa71fbfc11803b74444d66b5b0059ff78b9dc1beebf89b37bda5533c2912991b161aca61904d508c1e72bfb27f0ac2f7d94486aedc15d25b28f60bf2177c501992ff3
#TRUST-RSA-SHA256 45c3139c57d7d208ff6414e54559dcb4b61956a390e917483902cc8c20000adc55355b85cc01d9b0498321ad22fa195c2e2db23b4135c58cb2539c2c20809f634f48626e27123e3a8d1b53206493917d0e1a0d50c9991e1b83b7306d730252be6ecea30e2397e97577af16b511cc8e9a219f51ff85042e3dc59cee95a50bdb07a19b6ac85cf7fe0f00accea13228f888dc148c28b7ade4509a6ecbf868eb0b20ef3c848de3a73562527bf3655d878867a903edb0ee18644e3bf4e5d8d9120fb8ec845b73b07a2e602704ad465d8815e8fc02f86c0846cae6154a6b1d2a0a892bc972575741eea91482359b5cbc4445d8e3ce1aff2555d48ba3903942ad083c29fde2233d7460e4193de54a0811816c5fe92421d80dff455f42bcdb9eb860b204df39b5a17769e4a03305d9835b9b3b5bbb5c392d696442616ad1391cdd8db791ff1de2fda1bd95b3137c1b55eead71fd929c6f170adfc66734e8d379dbc3b8ed96f16bc262f7088f3c2f4aa2ed85fca92d9e951c741d44acc2548e10229c6fe287e8cd30aa0d7084e3c47bec85ab9c9d72b98cd6897cea486d54f706a37b3aa9431526648971de4c4fcb96a40b55104ac64f6de08d87b63fb8e1e037f538b1bdea6248c27723aa8bdd100f0d66a19906430608128a9d1725f94d2468086cfe1ccb734fb5c5fcb6e6f73d2ee96ca26a76198e80884484ac29b9493e53c5c173df
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162384);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/08");

  script_cve_id("CVE-2022-20664");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz20942");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz40090");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esasma-info-dsc-Q9tLuOvM");
  script_xref(name:"IAVA", value:"2022-A-0250-S");

  script_name(english:"Cisco Email Security Appliance Information Disclosure (cisco-sa-esasma-info-dsc-Q9tLuOvM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance is affected by an information disclosure
vulnerability in the web management interface. This could allow an authenticated, remote attacker to retrieve sensitive
information from a Lightweight Directory Access Protocol (LDAP) external authentication server connected to an affected
device. This vulnerability is due to a lack of proper input sanitization while querying the external authentication
server. An attacker could exploit this vulnerability by sending a crafted query through an external authentication web
page. A successful exploit could allow the attacker to gain access to sensitive information, including user credentials
from the external authentication server. To exploit this vulnerability, an attacker would need valid operator-level (or
higher) credentials.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esasma-info-dsc-Q9tLuOvM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4dcc8c49");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz20942");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz40090");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz20942, CSCvz40090");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(497);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

# We cannot test for LDAP or external authentication
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '14.0.1.020' }];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_NOTE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz20942, CSCvz40090',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
