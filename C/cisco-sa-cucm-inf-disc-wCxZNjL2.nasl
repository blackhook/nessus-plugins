#TRUSTED a704940b9577f5f67e8573e38f572b1b08712bb9484469c0efd5b0f6ac87e4d366af2bcc70f0e63899c90cccb4ed36643bde14aff4503222bc16a5f45c945ff90b26fd73fb2b14190ae87aa88651a4f75098410dfbb06687a5748a4b7e74ffb2cb00ff971c73813f44b587ab6d3665fae2ab1ff7031eb9bebd2b7d80cd0a76a26c30155a3d19505a0ef9232a925e9533c1473dedce0a0c0c23ce963ded7e1dd0828cd4b13d7ac00daba7488d9eaaeef8cc3fd47c3958ea1396ff0bb0744ac148afe6384693a54a59a6c6aac934040145c106785c3d5ab8d01bf9a80321ce37c9ea35eff13a80add80e996e350d04659bc2262e271ed24d90f83e910fd5014a5b8a19f4f7a3f599ea3aed900506cfa210b80701838b7b62522ca00510d1575d17472ec23c85c53d037bd5f6126910ef1bf45d84f24f260031472f65972b79d2f5f4bd5f325b46a65bd3871bb3040299b45fd066f6fd0a57444dc947ecd0cb7041857a3732889402ea73085b9ad71c813fbb41d82a83928d3e99fecb9dd867556dbc177ca0bde6c31eeeb5c9c1835fba5b1ea48e07c0f4c4990418f2523d3591f5ff97c08d116ee26495cb1dd32b925757d895ee59cf16a121f02e47ba973d90010e026208fb1095887b69cf88ea01579708dbec8c0f95ac5e8c2682c1e7d424c0f9d9583a05f6433ef9032003c22fba5c2df96b3299db8511587ac670f60e4736
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148694);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-1406");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv21048");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-inf-disc-wCxZNjL2");
  script_xref(name:"IAVA", value:"2021-A-0162");

  script_name(english:"Cisco Unified Communications Manager Information Disclosure (cisco-sa-cucm-inf-disc-wCxZNjL2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified Communications Manager (Unified CM) and Cisco Unified 
Communications Manager Session Management Edition (Unified CM SME) are affected by information disclosure vulnerability 
due to improper inclusion of sensitive information in downloadable files. An authenticated, remote attacker can exploit 
this by authenticating to an affected device and issuing a specific set of commands. A successful exploit could allow 
the attacker to obtain hashed credentials of system users. To exploit this vulnerability an attacker would need to have 
valid user credentials with elevated privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-inf-disc-wCxZNjL2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19df6492");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv21048");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv21048");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1406");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(538);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

var vuln_ranges = [
  {'min_ver' : '10.5.2', 'fix_ver' : '10.5.2.9999999'},
  {'min_ver' : '11.5.1', 'fix_ver' : '11.5.1.9999999'},
  {'min_ver' : '12.0.1', 'fix_ver' : '12.0.1.9999999'},
  {'min_ver' : '12.5.1', 'fix_ver' : '12.5.1.15900.66'},
  {'min_ver' : '14.0.1', 'fix_ver' : '14.0.1.11900.132'}
];

var fix;
if ('12.5.1' >< product_info['version'])
  fix = '12.5.1.15900.66';
else if ('14.0.1' >< product_info['version']) 
  fix = '14.0.1.11900.132';
else fix = 'See vendor advisory';

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['display_version'],
  'bug_id'        , 'CSCvv21048',
  'fix'           , fix,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
