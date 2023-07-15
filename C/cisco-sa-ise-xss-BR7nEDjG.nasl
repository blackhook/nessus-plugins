#TRUSTED 0deec52e5b0ffd4364a1f146b2c67901908fcfdaea97fa7403b8f3d4bf649b338dc7a930669d70162a57ca7f5766fe1235ffd7afa52985852c9878d951a1fd89cf30061a6fce55fd82954dec9e8c9b9370c5ed9b8ee697341e0c0838707411254632db7111cfc33a136fb6939683bdd93cee37a1f6defc6a2df2f683ff13b1536df4e9773918e6c8d5ce52dfe0fc91a3acce152735915aa219baa6cc10e98d4bac05552f3a62b272837a167de88292478b0a8d7d3c2331965cfba621e4b226381f24237cbe444bee60e4d2866bc0e8a99998bbf2b24c1aa29d9d9789683fc042053dd5bf1f6317f34aa785c51b22b624927b805d16acbe4e206d61ad3de5235099470694aa8c0c6b2513e17c2e04a1c908dd17a8e478bf4064960d3754789a27a491cb7d9d9356a197455a3a4f2c1bc04052179e94fe9d450b794afc489f64303782008ebbd380cb15a4dd0973d7024fefa0e913848124f3b9b85d732395cc0f54b36222e15449dacdd4e0d3b53e3057ca9874c75ac0a05a4c507ea6ce2ec4fc79fe83543e3da4eab816c191d678f793bedc8dbb8b0a0bb88d1048e29ffc94709ce846fc9810d47f2cc9a9f2c5ef51727e1b0ee9a752deac415f10a2faeee0e48f8ba321a1d7d00563c0e456d4e1cfde5e671fee4f8e50f543e853ca46ce16447b835341a5625af0c58524db2693e7d8aa21ca056bbb7719bc8ea4071dc17423
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135902);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/06");

  script_cve_id("CVE-2020-3157");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs44006");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xss-BR7nEDjG");

  script_name(english:"Cisco Identity Services Engine Cross-Site Scripting Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a vulnerability. Please
see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xss-BR7nEDjG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2391634");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs44006");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs44006");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3157");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');
include('obj.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

vuln_ranges = [
  { 'min_ver' : '2.0.0.0', 'fix_ver' : '2.6.0.156'},
  { 'min_ver' : '2.7.0.0', 'fix_ver' : '2.7.0.356'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';

if (product_info['version'] =~ "^2\.6\.0($|[^0-9])") required_patch = '7';
if (product_info['version'] =~ "^2\.7\.0($|[^0-9])") required_patch = '1';

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvs44006',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
