#TRUSTED 20c73c01a065504d5ef6b58a9f2d4da7b2818eddc3670af3d6e2329d086ff073011bdadf990e505831be8344e2809928926882152bc3c4e066f68f397e111c36c273a829a5db27776dac6006b476e79717851dc2b2a26da6206629040cfb753dcbf7f54c40e3603e2a255eaef0c17dbfc9967da42f3c227c812690e359a25dc888db527c346b17d703720188443c7847c20d2aa0ec5e0031af9a8ca2983872d8d90510bf2d478d77c61a672d3f0cf943b37b614048209676c2d1d5cb387a34d40205eaa75de6346674d896b03e16af6ec0e2c5a79791bb3983ff221d06478bb3507725da7a9f690e517a23ca1decb56afc059f1fce61ca71cdf5a86db430abb30be9cdfbef30f42a3c137ee5a391f2cc48204065fe04cfe60404234ed7af3df0d0ad2639b5e7075f47aef45e308c6b28e8ab72946cb2a65148c778961cc65e6f821703216c2da2f8354ee5567f6d9a02720b1ebf175e2a9b2d3bec46622753fb621c40415ca728dbaea38008417bf988e70ef8e49375e90e4b1825ae1e4d1ceef8017c0f7316b719095934fffc83c86d2e4e693d91baca398696d76f223d92e98c881dd07aeb7e31274ed0b4d8f61976b135493a87e19856bbc31004097870ba6f061654d7a5700c92fed07e1423f9a8c257a33b83e9eed55ad13e10feb9466199c9b69fa7576b0b3f1334937130308717fb4012ecc462ecf9887a6fe50b8174
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150052);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/28");

  script_cve_id("CVE-2021-1470");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu92477");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdw-sqlinj-HDJUeEAX");
  script_xref(name:"IAVA", value:"2021-A-0118");

  script_name(english:"Cisco SD-WAN vManage SQLi (cisco-sa-sdw-sqlinj-HDJUeEAX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage Software is affected by a vulnerability in the web-based
management interface  due to improper validation of SQL queries. An authenticated, remote attacker can exploit this to
execute SQL.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdw-sqlinj-HDJUeEAX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e0885d9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu92477");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu92477");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1470");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '19.2.4' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.2' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' }
];

var version_list=make_list(
  '19.2.097',
  '19.2.099',
  '19.2.31.0'
);
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu92477',
  'version'  , product_info['version'],
  'sqli'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
