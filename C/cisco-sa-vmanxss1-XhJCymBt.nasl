#TRUSTED 56709786128b89032a995f749e39e10e238c30a1a8ffdd44af8096d915548177af8f804f539e6c9d52c97100844da443f86708707e175ed34505183c509ed373d912989828df0181ce92aaf73791911ed92b6145eae2ebc8fe1e02ceff4146a60ee70240a788ee142596331121608847beec2bfc8a5b706f44c2cbfd5869ae4896c9182a4db7bc52eecce3d4976dda564729ac59746955d4c2203e70811cd148e42919388cc947f9d3a134586a8c64784ed7071d0c6b0e89825792aaf35731a872bf262c2459e2761dfcb0d6704fc7432d8f59cf350d3493de55fa97e9cbd57d9172a0f8f525bb47a2aaada15dab6f8d9e51d02f0d76425b537260541b010b71c18d824ccca0d2074cf809ddcbf59916d375dc6954dded63e3f0e535dbe986a701c97208fbfd8f99921dccf6aeffa0adfb9205e330cf00ea7f868fef4c365f8a930741cf390ba4bcdbb320d4820ca941fe425a97d71a63c5fe97b2edf863c3ed4d2800038c2b5a14a15d3b9ec98d92ed427490d1a8a3605fb979ddda1314cc3a7345beb0336cd0123ba5705d1339ba9b9ab3cd454be9061b0c95264571c71c68cbd9b363503ecb4daa231b43c32944d711c9f2dfa9422ee65645ef17e829dc41bdb59175eddefde9def6805b68463eef239d0003afe4992bc02fc395020d766acd236b548a7814cafab10b8255068e56fe0090fd1ad462db73af31abe1a281ae
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143216);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2020-3590");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv42614");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanxss1-XhJCymBt");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software XSS (cisco-sa-vmanxss1-XhJCymBt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a cross-site scripting (XSS) vulnerability
in the web-based management interface due to not properly validating user-supplied input. An authenticated, remote
attacker can exploit this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a
user's browser session.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanxss1-XhJCymBt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca524673");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv42614");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv42614.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3590");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'20.1.0', 'fix_ver':'20.1.2' }
];

version_list=make_list(
  '20.1.12',
  '20.3.1'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv42614',
  'fix'      , 'See vendor advisory',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
