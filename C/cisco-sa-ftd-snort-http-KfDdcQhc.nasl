#TRUSTED 69e58561eb0c386a2296df4d5f18bdcd307b6ce03cdade906fa0e269917bead7f902293dd6ee11cdd0ef93fd6b4f5a37ea522cb724f05ba21381fed2adfd4ffce60b80502d5486e7941dab2c137523e7a6ac5df620e65fd8e9debf1397f670c29e3640e159cbae4328c387113dbaa05c7e41209a538167aceeb5b0392dea68757b21b3eaf324963122983f32bda53f8d8676720bca68a849fb7c8c38f71ab9dc7958770b50ca61ea3f8dbc6e47fe70700355c2c66ca9477fdbcfd7635d26a2f53a00c346012ad1651da147d39b1fd86ee8c2ae5a3369fe067d0da2f095528035611b8fe75a03144109e8f71af9bfd9b62e03e0d82ffbe6f1ecde1fe773132a8f78ea4b7eab6e2488caaa1adf7945f03cb12574d35224542977a9a945864775966609808e1c4ce2d484620873e33225434983e6f25d2d9fe5f22baf2632fbd756516fbd86bd2e66e562d43b0bb856e663a5d0090a1b7ce756c09fe55afc79111b7177c74dbcd5d256fc12b78fd60784876974d9810dcd72cc7a8d3c4ef4ce16089e7937622a748286b18d99894f6e78a6117eee3ae8791569cedb96cb9c28aa00b70c651b7d53cda09c86ff2510be87e3ebd86a5ee1b464e1cd5dd9cfee6e9bcb3aba16a52d02252a065c98aa0ae03f719ab96160703b70fdaab1cbe699e487978471f1d1e56e063b2425390efa53e814bc405a013b5face1d26eb8acd3cf8157
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150059);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/31");

  script_cve_id("CVE-2021-1494", "CVE-2021-1495");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv70864");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw19272");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw26645");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw59055");
  script_xref(name:"IAVA", value:"2021-A-0249");
  script_xref(name:"CISCO-SA", value:"cisco-sa-http-fp-bp-KfDdcQhc");

  script_name(english:"Cisco Firepower Threat Defence Snort HTTP Detection Engine File Policy Bypass (cisco-sa-http-fp-bp-KfDdcQhc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE is affected by a vulnerability in the Snort 
  detection engine due to a flaw in the handling of HTTP header parameters. An unauthenticated, remote attacker can exploit this by 
  sending crafted HTTP packets through an affected device. A successful exploit could allow the attacker to bypass a configured file 
  policy for HTTP packets and deliver a malicious payload.

  Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-http-fp-bp-KfDdcQhc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d5152c8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv70864");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw19272");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw26645");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw59055");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1495");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(668, 693);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}
include('ccf.inc');

var product_info, vuln_ranges, reporitng;

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0.0.0',  'fix_ver': '6.4.0.12'},
  {'min_ver' : '6.5.0',  'fix_ver': '6.6.4'},
  {'min_ver' : '6.7.0',  'fix_ver': '6.7.0.2'},
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv70864, CSCvw19272, CSCvw26645, CSCvw59055',
  'disable_caveat', TRUE
);

  cisco::check_and_report(
    product_info:product_info, 
    reporting:reporting, 
    vuln_ranges:vuln_ranges
);
