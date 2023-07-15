#TRUSTED 892b1cea74527438099b2113225d88bb25a182c01f59879c5a9b57dc19c7d4d1c21b378b5b4c938b1a184f9f742e43c503f0b879cf21031dc4154ea13efecf20eafa1b7fa379cadb67d3b91908f69c66c9701c656bc7990d6f3e480fbbb296ba15d8252d9f47e905ed6c828686f0412bd470b62f45da58ed5b28affe0c5eb52cda72eff7ee02bc7405e5218d2d6e7562da466eb82f486217f1266dbefe654783ad19bc6ffcdd3a538c8f59daf69342114bc8569b3cc05590fb4afe96b744316b8fee40645a3674f147ab11cd2756714c65d8be6d670330824213a348ec4918ec12ca4a839cc5140caff544d5fafdc7b386a6888ee99f2b05642ffb2b8c92839eef2213291f7c96f13d75b304725d1e1a9e0419dc0dec64ccc0f7dc4fb86082877a73a63710b8b60f57f655578ab20929681d8990d28da45e7acd0a0f81c71025ffadfcc42e0773e6603711e76dbd95e5634ffda3a3b4f07d17855261dde2988443ac75a426cc2a181852ced6f254bdb8744915edec1dfb2668c58f660e47f7abc78fc4a5d66301466dfa461cefbffb1b1cf2134fc452fba3031f13f6c2eb4875b41a05c838d7cadc88b2e89a219ee0cc526e5a0573033c8426288b8fef638a2a86b8c48d61fc2d739763a164ddadd922a94175897dff0734b2afaf4af8aeb32fb5b27dade4cb86d330501643e8f15b3f941729c68a7aae853ee01436108dbc58
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152961);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id("CVE-2021-1582");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy64858");
  script_xref(name:"CISCO-SA", value:"cisco-sa-capic-scss-bFT75YrM");
  script_xref(name:"IAVA", value:"2021-A-0403");

  script_name(english:"Cisco Application Policy Infrastructure Controller Stored XSS (cisco-sa-capic-scss-bFT75YrM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller is affected by a stored 
cross-site scripting (XSS) vulnerability in its Web UI component due to improper validation of user-supplied input 
before returning it to users. An authenticated, remote attacker can exploit this, by convincing a user to click a 
specially crafted URL, to execute arbitrary script code in a user's browser session. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-capic-scss-bFT75YrM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9366d73e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy64858");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy64858");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1582");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}
include('ccf.inc');
include('http.inc');

var port = get_http_port(default:443); 
var product_info = cisco::get_product_info(name:'Cisco APIC Software', port:port);

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '3.2(10f)'},
  {'min_ver': '4.0', 'fix_ver': '4.2(7l)'},
  {'min_ver': '5.0', 'fix_ver': '5.2(2f)'}
];

var reporting = make_array(
  'port'     , port,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy64858',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
