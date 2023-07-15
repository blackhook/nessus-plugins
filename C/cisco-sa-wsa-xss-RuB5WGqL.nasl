#TRUSTED 04ff0ab6528acf5ceeab24f1f4eccac80be103aefad380ab6a2fe36849dd8c536d718f07b5a4ff82711745176068640304d4068e3ee09ba1bf535a9099c157ec5ac22cd500269226e3e5729e44cd0f66259b1459082362fa8384a80f31e298c52e2d7f35a6f6dc1b552a6a76aea32d938c9eded9f7a5f062adebce8f5c80e2f0dd2c9e932c29d1e942064f8dfdba9f0f6b010f195aa95f535cb57fd41be0422b3b75a92797a25f03e73cb3e5f421b1572d837b3a5770e5e0012a16a33dcac06bac62e0a6871a9d39f915dbc9e3348746f97b4cff10defd19ebc2e8384f05682aa905673ad57b71bbf758b147dde3d251914bf8434f8cdb9129b98d94fbf0b2b1250d09b3480bd0af0070fe4444d91d782ae12b866b32cd37e9bd9c414bf292e057e774e4405951692e93d051fa7f7668f5a3e2b7fc47e36b02ec8b699666783ecb34a387f6ff96c9db7e9602789708c7844c8f7075c1f37445981e9ba580a87802121199fb4e1a38b858087931dff41f70f0ac63b32b9cd0e38e06402db0f345a636a5357d61cd2700384a482b3521abc7d7eccafc3779ad13ea452179cace2386c231713724897197ca095341467eda13a5f9a44611ddcfde4df95a928f35762a6d732118c100dfcc80a667bb18b409739bf808996cfe3902e5c2aa014dd6b34847ad8bdaa32c0750082517e24d7b1ef5481c288ca9759b89ff87e93fa639a5
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149809);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/15");

  script_cve_id("CVE-2021-1271");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu22019");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv27761");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wsa-xss-RuB5WGqL");
  script_xref(name:"IAVA", value:"2021-A-0050");

  script_name(english:"Cisco Web Security Appliance Stored XSS (cisco-sa-wsa-xss-RuB5WGqL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance (WSA) is affected by a cross-site scripting (XSS)
vulnerability. A vulnerability in the web-based management interface of Cisco AsyncOS for Cisco Web Security Appliance
(WSA) could allow an authenticated, remote attacker to conduct a stored cross-site scripting (XSS) attack against a user
of the interface of an affected device. The vulnerability exists because the web-based management interface does not
properly validate user-supplied input. An attacker could exploit this vulnerability by inserting malicious data into a
specific data field in an affected interface. A successful exploit could allow the attacker to execute arbitrary script
code in the context of the affected interface. Please see the included Cisco BIDs and Cisco Security Advisory for more
information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wsa-xss-RuB5WGqL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad8556d3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu22019");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv27761");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu22019, CSCvv27761");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1271");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");


  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

var vuln_ranges = [
  { 'min_ver' : '0.0' ,'fix_ver' : '12.5.1' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu22019, CSCvv27761',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
