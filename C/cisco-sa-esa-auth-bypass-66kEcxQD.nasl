#TRUSTED a8c3b3a4427d2e5a2addce0152679daecb4cfad6a1c9a84663e8f3a33435f57341cedbb4fe57c13824c4106baab94bcac8dcac738e25e92fcf8f31b3f71b4293dcf9f3119f81dea5157085e3c1f06831a035dfd4b72df9373ac73749f6f78389f2900cbafc4a89bdd45b04995d566ddcd01e4effb916605807a0aeeb6c8ef29eaf6f06f79b37e7b0520564b934f2f0aa643745d82cf531c8fa4c13e34648ffe38c255e67a9311bdf670323aa6f1428d07a281e0649c5656a9e4b74b2a68123d3453e01217dba0955caaa36f8ad6691316d8263a9d2f9c46b4b32fdcc92d56ec6c7ae1b8cd9646a376626481b3c70c10855e511bf481bfa727c5675d51ec1fc23d04a0f7c468a3c39a4eaa795873298fcafcb17f48180f0e6adca7821de69145fb609d19527949d6c64c0228884b34e8f66ed7f119a4231778e90fd35589fbe2a11e4dbca1afcd0275c1435fd92eb9bb8711b5e4c2a7ed88bdaff9de599be41e0fe3ea8ed1311d09f676e0384b97467e6ab213d34e52c7d8facba88c65796d4938ee952a04c84de55af42a7f8f3dd5dc71d0fe47bca4c56843c2fb7ecd81cbf6f4967703502c27a10c0c453d6cdf69b5c258f2a8fd53bee8cf2f1851bdfdc9c88035750cde29a9e9e7508606ef6cbe9ea8e13ed52ae00bc9409f7a21b3f77ad4896c7539f0f17e90eec199495049ace08a3d7d2e383224d407e3e2d4d3a582a71
#TRUST-RSA-SHA256 a073964a458bbd5e9db605ddb299ef6bc1a01fe464a434905efc3b0f7dc81cc61d36ae49e9ecf321845ae93aeed4b3b4fa6eeeedcc353c20495546a525c75f84fe3628f3d178e7ba76378cec373a534f82a39fa2804baab8ae7748a73c24b32d1d5b02f12263741b8243db6a011f3b1c9ab9b44f435fd03efaaa8aa7c5cc568e78b661dfc63442f4a7290a5a3f42c34b873ae69638fa18c5067afa46f273f61e9a9a4b2851ffce79294eee4fb32d958a374dabbdcf2494840bd8a8eb4e52b66d83c2859302ba2fb829075983c43d7d013cecb5c58d31d689c1339826db148e7b792422c0ca0d5a2c7bf9b2b14faecb366c370ee10541b047d29eeb7d820a82d0b5918c430fbfecb5c1e972745ae989f0069678cd1ca43f6503413827943605cd1e984d2a8d5f6c8307f17894fcac563218f23fcb206cd676b633c5955b9e0e0d144c9de025f8063f2a7936d609b883806fa5b30ba555ec26b2705a6eb3c710608474ae39264698bda36d4be5cf93317daec589d43e64c9dce29ede36272823a7b5a00ae04f5775113333e200ceef5186837fff05bfa79a4ea28551ac3ee34950e8162b5dac5b7541c0fc754cb50b38a4851aaa802221295534a6eb3602b1ffaff82bc06b10116da6d115642a5c5d7003ff7f5ae7b220aa90897f0152bca92c14b708c64aa46619e63220f92e497f1395e44332fe04ff9612ea4d8c205998b038
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163476);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-20798");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy13453");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sma-esa-auth-bypass-66kEcxQD");

  script_name(english:"Cisco Email Security Appliance External Authentication Bypass (cisco-sa-sma-esa-auth-bypass-66kEcxQD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the external authentication functionality of Email Security Appliance could allow an 
unauthenticated, remote attacker to bypass authentication and log in to the web management interface of an affected 
device. This vulnerability is due to improper authentication checks when an affected device uses Lightweight Directory
 Access Protocol (LDAP) for external authentication. An attacker could exploit this vulnerability by entering a 
 specific input on the login page of the affected device. A successful exploit could allow the attacker to gain 
 unauthorized access to the web-based management interface of the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sma-esa-auth-bypass-66kEcxQD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf454769");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy13453");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvx88026");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20798");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'14.0.1.033'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvy13453',
  'disable_caveat', TRUE,
  'fix'           , '14.0.1-033'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
