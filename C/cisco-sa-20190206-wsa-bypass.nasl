#TRUSTED b1dd0a502d714bdd1cf26b6bc7fd5a81f08468b6a70c3761d658da82f2a57f179fbd13a65ef171670177628aef25ea30d6fab074285f0cdad3fe9689ce55503db1789fbbef57fe356f6007022fa51d7c2703e2d929696787011545362353632f2c55e1bd6db4d91f5654b3c26b08dafb8b28ba0bf6cc5754b89b04cf996d190b9a202db0b453c90840219baaf1f9b2cce787f9f37c7a6081aee172b9a7cd6288e4b7e73a57c3d64b7b7dab871d946b5d904d1c8ee07112d79ab49234540824187fb07df8737716c3cd48128df38037c43d523eec510745dea5124e96c469542daa8e55f7f8e46efd35b187dd20ade200b13b277e4a9dae8484a4290682d607e5ccd8a76ee1b13894c6fe4e9df3d975ebc95570eec12ca2c0e13e7e45b8cad0827860138f20ba8682e8a6f187533e328fafe7f748a664e0654d7429569cb0ac82adf136dbf4c647e8fcdec98bc3a2de57f6e573319f8c816e3817b5cefb1dd76f4dea62783f8a56461f3dfd0336f383df4ee219d6d517bf5f0fae8519a19dba2fbe8153d7468036992eba49c1838738d874a8006aa5344ab59606b90eb3d24c6a8e820becbad02270457f9a490cb1a3438f6b1048e165ae776609475896d5b9036c5b7cf6e30ff762a67791c22248af2bb22faeee6101c99a4e79dc1827cd077bafe5939e90f6c62835c1721210b586cc126909e146881dbfc1b412aa9bbea05b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133958);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-1672");
  script_bugtraq_id(106904);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm91630");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190206-wsa-bypass");
  script_xref(name:"IAVA", value:"2019-A-0219-S");

  script_name(english:"Cisco Web Security Appliance Decryption Policy Bypass Vulnerability (cisco-sa-20190206-wsa-bypass)");
  script_summary(english:"Checks the version of Cisco Web Security Appliance (WSA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance (WSA) is 
affected by a decryption policy bypass vulnerability. An unauthenticated,
remote attacker can bypass a configured drop policy and allow unauthorized traffic 
onto the network. Please see the included Cisco BIDs and Cisco Security 
Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190206-wsa-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07bd84fe");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm91630");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm91630");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1672");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

vuln_ranges = [
  { 'min_ver' : '10.1', 'fix_ver' : '10.5.5.005'}, 
  { 'min_ver' : '11.5', 'fix_ver' : '11.5.2.020'},
  { 'min_ver' : '11.7', 'fix_ver' : '11.7.0.406'}, 
  { 'min_ver' : '11.8', 'fix_ver' : '11.8.0.410'} 
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm91630',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_ranges:vuln_ranges
);
