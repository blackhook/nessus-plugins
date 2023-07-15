#TRUSTED 7e23a11f8af0066b3bc652097642d7274ba9c049bbba449b4c2e9f90805f3cc07364cbd45dca2eeabadf7024fe10f2de482a0fd2090f8eadf155cb58655eb1c5d2f8732f1200d15ae6f0b299a9d5f514dee3b471c8349ebf04a0a98584181089ec75e376d5ac6b18680e255c54d127858dbdf3fa1cb0f82e49041cfae8480195d36f012502afb2bd86bfce31d40ac266dd6274862cad3a317f67ad8fe0a32f7e96bfb20bf64256e9d25d968eccc4f04f6cc5c48e86aeafd91d1c3ef37ae408d4efdb197e7d0a4c789dbf8403213cb6d217eaa4a47370e63a6b33a56ee1ccbfa56b716bb5938538183bebb2359d70c783d179bce50f2a385e364f6dd11bd794af26ea9112c5f3708580962cad1194f2cd2b14dcff6a8aa3dc31ba5ee416a0c4d3d0ee8c45f57fa4ba9a020094002ec1abca065d3ef03d75217c417b57a7346e108b0cc304c3e54a9f564b394a960ed4c8f893b8af5dd5812f35eb9439d0bc242c3ee6abf2f08e097a64aefab9279df02c7f68c62f6303d1e93edc614687b42662e2a13bb2f6e56c023f27312f4f4ee832573598643e7f0f533d0468444ca55375a8b12768c098ea59a2bcae8cbde43e4ddb96c617be45ba6411ed7a6281447d0a1f35018fed27887b50e0138a54106839c58ee4a2bf21814ae714ab868cb5079a1282c4ecd89c7e21a09c8521e581b7313d6356c106a2d20ae676a9b1ef11eb61
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146057);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_cve_id("CVE-2020-3456");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo94700");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp75856");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fxosfcm-csrf-uhO4e5BZ");
  script_xref(name:"IAVA", value:"2020-A-0487");

  script_name(english:"Cisco ASA Software Firepower Chassis Manager XSRF (cisco-sa-fxosfcm-csrf-uhO4e5BZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance Software is affected by a cross-site request
forgery vulnerability. The vulnerability is due to insufficient CSRF protections for the FCM interface. An
unauthenticated, remote attacker can exploit this vulnerability by persuading a targeted user to click a malicious
link. A successful exploit can allow the attacker to send arbitrary requests that can take unauthorized actions on
behalf of the targeted user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxosfcm-csrf-uhO4e5BZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9412e4c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo94700");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp75856");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo94700, CSCvp75856");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3456");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

# Firepower 2100 Series Appliances when running ASA Software in non-appliance mode
# We cannot test for the full vulnerable condition
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (product_info.model !~ "^21[0-9][0-9]($|[^0-9])") 
  audit(AUDIT_HOST_NOT, 'an affected Cisco ASA product');

vuln_ranges = [
  {'min_ver' : '9.8',  'fix_ver' : '9.13'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo94700, CSCvp75856',
  'disable_caveat', TRUE,
  'xsrf'     , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
