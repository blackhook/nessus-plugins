#TRUSTED 9a381e8ad9834ff48cb3de7abd10c8470cd015961a8723735904464e37fe5a8d82273c35d9e133db36566a1e6c8d65caeb69e83d4af465b6055ca62381797daf4825180aa00a28c87c48f53c28cd84fefb84e55bdf402e7a3a745a93cd817917b068493d44c7bbb8aeecfa53790734fb51b3b35f57124613863eb9fcc3ccdfb05ea816d0b931c12b57b17d85968c9fe4ade081ff81f35b7a5b8f9dda643e5530079457a993796e197bbd3191cbb9181545a4c8a6c5ba88ca6517642db65f13907483a3f7420410c973f8d10fe00581de4e00aa99b3c6b85b8cf4512fc674d330a4596c304be00f3dcf3492a717c4ee248b414266792ed0df642e7f2e2a1af186819018afb03076e3ca900ccf209b59f55dc68b06b03c051e7b3afbfd138cd3e58f9f7d6a7eaeb4e3b4c7bc07a64a84257d503a31e2b72194af053f1a087845b21c718ec3a0637bf67a982a7f41b63f13437864966e20f096f6b9bc57d8eb19b2fc460aaf0e25a7ede0f2136e3462bb6926bd91e9cf7709069085abd85e38efd214b569ef280f1a2993696a061baf30506dde3c72831e69d7867daba417934886423ae2fbc4e3adc7f7501e0c32827e4a65cad668859bb81bd15034ef07f6e070fb36f145dcf0233b7ec9578df571b9b65f60be257103c071012407f2b5fde763252fd27be8b4db0b631ea14d277cf9ca1034c899b63b41fe0912f91750e90812
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134231);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3166");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr09748");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-cli-file");
  script_xref(name:"IAVA", value:"2020-A-0085");

  script_name(english:"Cisco Firepower Threat Defense (FTD) Software CLI Arbitrary File Read and Write Vulnerability (cisco-sa-20200226-fxos-cli-file)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense (FTD) is affected by an arbitrary
file read and write vulnerability in the CLI due to insufficient input validation. An authenticated, local attacker can
exploit this, via crafted arguments on a specific CLI command, to read and write arbitrary files on the remote host.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-fxos-cli-file
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0375756");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr09748");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr09748");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3166");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_extensible_operating_system_(fxos)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');


vuln_ranges = [
  {'min_ver' : '6.2.2',  'fix_ver' : '6.2.3.16'},
  {'min_ver' : '6.3.0',  'fix_ver' : '6.5.0.3'}
];


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr09748',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
