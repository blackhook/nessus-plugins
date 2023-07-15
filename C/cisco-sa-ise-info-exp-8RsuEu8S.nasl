#TRUSTED 7660ce75ef9eb68f92c1b960472dab0046546e606e3c67994141b10c04febc567b6833a1096647756bdb3df32635b4fe4e77ad6cff77094f8c1425f328e3424ce0c64202b3c849b1b5f866325e0e2965310d25d948e7380c33baca70847bfeea627a1ad021883f461610fc0c8a88c36c2c8e07b9f5ee6419c49ad208c647752afed21fc61b62c2e01b0ca2b44b547a2b7b47339bc8f75071c2cb50a52a4e6bdb7f6d482bd759f4847b8860d41bd6ed0d21b5783021da5309de36f29c940cda5fd2d84193af101858bdd43962416343a323e8d3e0f47078cc4a079c5f847487752699e8837bea431d1edeaaea3de09d9610e6881d7eb03e7661b00d8706de6a870c5fe634aec1c0bad5f12b7d1df4d2e945f57dc6e2e5a949a9ec3c64e4ca1f8c99d73fd564dc8362339f83e08cb90c3103adc004eebb84a9355283e9f941178a52aba447a2997cd58b996b27fbcc3e67a9899a477136179b579a85d93d45acd92321a53423d018defc7bca7a24618c5cdc82e8ac60164cf612eff2c7f4ec25c08e0dfb345ffbdb27ade7fe3231d12010150718f8b84fd689e3cbceda3c8817c41cfbe6ce01e4418dcd25e88cb368d9246c59f39c42e2ee39fca507c3d8e6fadbba9c4823bc17e19a64357619a2e03f580b0c15a54f198a550df21c942d84999ebbe403589fb19c09c63480d3549580b8c2f32ab0322f64b39a2042e5b3eeeabd
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146618);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2021-1412", "CVE-2021-1416");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw81454");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw82927");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw83296");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw83334");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw89818");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-info-exp-8RsuEu8S");
  script_xref(name:"IAVA", value:"2021-A-0097");

  script_name(english:"Cisco Identity Services Engine Sensitive Information Disclosure (cisco-sa-ise-info-exp-8RsuEu8S)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by multiple information
disclosure vulnerabilities in its admin portal component due to improper enforcement of administrator privilege levels
for sensitive data. An authenticated, remote attacker can exploit this to disclose potentially sensitive information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-info-exp-8RsuEu8S
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2918dd6a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw81454");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw82927");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw83296");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw83334");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw89818");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw81454, CSCvw82927, CSCvw83296, CSCvw83334,
CSCvw89818");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1416");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1412");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

vuln_ranges = [
  {'min_ver':'2.3', 'fix_ver':'2.4.0.357'}, # 2.4P14 
  {'min_ver':'2.5', 'fix_ver':'2.6.0.156'}, # 2.6P9
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356'}, # 2.7P3
  {'min_ver':'2.8', 'fix_ver':'3.0.0.458'} # 3.0P2
];

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if (product_info['version'] =~ "^2\.[34]\.0($|[^0-9])")
  required_patch = '14';
if (product_info['version'] =~ "^2\.[56]\.0($|[^0-9])")
  required_patch = '9';
if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '3';
if (product_info['version'] =~ "^(2\.[89]|3\.0)\.0($|[^0-9])")
  required_patch = '2';

reporting = make_array(
  'port'           , 0,
  'severity'       , SECURITY_WARNING,
  'version'        , product_info['version'],
  'bug_id'         , 'CSCvw81454, CSCvw82927, CSCvw83296, CSCvw83334, CSCvw89818',
  'fix'            , 'See Vendor Advisory',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);