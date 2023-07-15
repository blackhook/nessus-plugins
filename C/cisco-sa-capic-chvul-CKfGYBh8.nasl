#TRUSTED 61ceab70532bb32aba71168fec6a2d31d708b65b2ad8355f23e811a24a585fced6de56ee33c71181e46fd6dbd17ef9cf94073e6ede78e4dfce631bc2c53c037ecb060766767a5586b7545fbd069854e9c1a382dc70927e786bfe492d7602a99f60dab2335b81545f28200b076c2d43276138333cc98e805b4e4a2a6e44649a1b5d4fdd5c6d964e167770bcf9820d1f4a3f16ea24e4715207ce784f642f25f6c9abc932ca2f466d70dbd0dec44e9e485baa5bf5f445fc9ea0323ef833f8ddd7a828e77e46d9d738247d02596a2dbeffb8e294b1688079e4a72aa568608541e0727b35f1bc357fe8b7ec9c04aa808a40432e331708d6e8cc8b51f9cd24316b4c671f5152d11f2210292cb7214b3c9eba353fe415aef4f253ceb684630e5776ae700ecccda5fad3e27abffea808fb6676af5138a428dbaa6bb0f6ca2c42a3af59d6af863b9b5065b421411f0d72fffaa11f3adfac28fbba2b689d7c505a50708499bffbf026c745f0b51b1bd3c3837d147c3f442d05c7ed4f7c67c8cd232321a13d65165e1c274d4dd596f425e17ecd8d4c43a8d0460a590be962058a297b055afe2513baaf2d45b4545522494fabab6d1dada66897e694dce38c75362a40247e79419a217f535d49c67afde6bbfc327753bba8098ebad8becb41fffc5397632340cfea52ad1bd0cfba4116d87af08cad565af02598f2172e1649a33ccfadc74ced
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152974);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id("CVE-2021-1579");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw57164");
  script_xref(name:"CISCO-SA", value:"cisco-sa-capic-chvul-CKfGYBh8");
  script_xref(name:"IAVA", value:"2021-A-0403");

  script_name(english:"Cisco Application Policy Infrastructure Controller App Privilege Escalation (cisco-sa-capic-chvul-CKfGYBh8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller is affected by a privilege
 escalation vulnerability due to an insufficient role-based access control. An authenticated, remote attacker can 
 exploit this, by sending a specially crafted request, to gain administrative access with write privileges on the 
 system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-capic-chvul-CKfGYBh8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6b0162b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw57164");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw57164");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1579");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/02");

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

var app_name = 'Cisco APIC Software';
var port = get_http_port(default:443);

var product_info = cisco::get_product_info(name:app_name, port:port);

# Not checking GUI for workaround
if (report_paranoia < 2) 
  audit(AUDIT_POTENTIAL_VULN, app_name, product_info.version);

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '3.2(10f)'},
  {'min_ver': '4.0', 'fix_ver': '4.2(7l)'},
  {'min_ver': '5.0', 'fix_ver': '5.2(2f)'}
];

var reporting = make_array(
  'port'     , port,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw57164',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
