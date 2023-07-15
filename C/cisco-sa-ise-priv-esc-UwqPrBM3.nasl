#TRUSTED 11b0f30bc7bd9428bc97db42a1aa37066856fccc40750cce1bbd6cf0c46b8bbdb4e7e6b8a2e7010b2f66b91e97033b620723e526685144fda8b552098be4c9ca286799d6ba9d924134465f5f81d9de913a19b1ba38aba77ef77dc4857efd4785cf8d3abaf72e3168f836eb8fc1d399c486a316364232e35c46bbe75db623ea567c715e3def2f5347afc202b78b19b55397d06fa0e827bc8e83bce440208f49965024584cfa9d74349c2437d5323b84cd1d123482ff797fd40b977e0a6117caf9da16123931392c9313765eac2179310f67d213a5d0f50b101c8b8b26fe13d3bdf5d861659e48de25726514270c1cb1a648d73fc81fd7e22739482103961cacdd4640c65bce708cfdc54b9d62ddca10e86fed2f113609e3dd1f2dd9b33747fce3559b028b1422bf0da702f058edd566f055766572b6797643afe510ac957d9733b0613a0bfde706780bb40a48b2d890362574ed409a0beade185c59bfce2c9ccec59815e463cdf6e758616e6a146230e78fb3e51d0fb9c097afac5b5c35d8a362e41bcc3cb86d4ac4355ecf5696b759fbcf7e2dc5bdb9caf31565c5899b5b4138789df9d3c9052caa1fe6f4947ed6594470b632612ba5d2bb360e26f12e81680f977a511435b631b57c639bfe613176ccf0c6c10e49b167cace4169acc1e2b6f545806213d673514433f11c50c4c7ddcc6ddf990dba5f1cd472dea8b0a2754f5f
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153947);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id("CVE-2021-1594");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy11976");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-priv-esc-UwqPrBM3");
  script_xref(name:"IAVA", value:"2021-A-0455-S");

  script_name(english:"Cisco Identity Services Engine Privilege Escalation (cisco-sa-ise-priv-esc-UwqPrBM3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by a privilege escalation 
vulnerability in its REST API component due to insufficient input validation on specific endpoints. An 
unauthenticated, remote attacker can exploit this to gain root access to the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-priv-esc-UwqPrBM3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?868c2d87");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy11976");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy11976");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1594");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/08");

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

var app_name = 'Cisco Identity Services Engine Software';
var product_info = cisco::get_product_info(name:app_name);

# Not checking GUI for workaround
if (report_paranoia < 2) 
  audit(AUDIT_POTENTIAL_VULN, app_name, product_info.version);

var vuln_ranges = [
  {'min_ver':'2.4', 'fix_ver':'2.6.0.156'}, # 2.6P10 
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356'}, # 2.7P5
  {'min_ver':'3.0', 'fix_ver':'3.1'}
];

# Double check patch level. ISE version may not change when patch applied.
var required_patch = '';
if (product_info['version'] =~ "^2\.6\.0($|[^0-9])")
  required_patch = '10';
if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '5';

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvy11976',
  'disable_caveat', TRUE,
  'fix'           , 'See Vendor Advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
