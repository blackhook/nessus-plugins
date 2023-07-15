#TRUSTED 54668847412782a6d42c0f8a423ca274bcd1b820c73b5fd67d575afaa4a6fb47ce75c79de1db37211c5083ad0f84c636877ba19c1b3ce80e3c35f4e56771da7fac16bb9aa12539edcc3e9cf4004c955a94227fb15da63e0b9c731236a1209d629e454df67cfeb088a18e50d6ef373062c2623a07ac69c2b66f559eff11c3025bfb2966113754502011b10f5a923e3eefa2015d1f4a0678fb6007e11e4f47425e05746258d2b64ac758a92821c4abe7e7e9cc0630be512eac18d612c9d53adf1d3f48e7238a25c3076898a012c6ad32b6cad2a309226b0f64b914677d1c32de2e0c3d37fcb356c3f271e3ef0d434859629b4530452af11a514400515729f7339e860bb0a17a1fd822d84e29bd8d460aa4fdc171150869d16a4fabbe491eea5ec00915d375bc59c675edd710105ff73e9c0b2722a3a18f1337ae11351154de437318b08459de57d252ad340d62fe8c12b8031336affe090d4211da9cc99b4ca98e9696dbe5c3436567762758f7a07f6ba3133cefaf99e8817b7a85f56ecd28e2c4c62f446f40a6d3f829618018aed90c86d20e08f05c19ac4b34b5efcb0a9a5d1deb8a46287f8861a735aedcca33525fb8174b5e857ac0e20248f71aaac08f94d25c55fbc0c397ddd4f6f8b47fa85c75898471ea8db4259a49953e319b790d5867590e2e92eadd989a743e89688aa315036754c62f40a43de69f988a2d6be9d117
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147756);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/16");

  script_cve_id("CVE-2020-3468");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs21296");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-v78FubGV");

  script_name(english:"Cisco SD-WAN vManage Software SQL Injection Vulnerability (cisco-sa-vmanage-v78FubGV)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN vManage Software installed on the remote host is affected by a vulnerability as referenced
in the cisco-sa-vmanage-v78FubGV advisory.

  - A vulnerability in the web-based management interface of Cisco SD-WAN vManage Software could allow an
    authenticated, remote attacker to conduct SQL injection attacks on an affected system. The vulnerability
    exists because the web-based management interface improperly validates values within SQL queries. An
    attacker could exploit this vulnerability by authenticating to the application and sending malicious SQL
    queries to an affected system. A successful exploit could allow the attacker to modify values on or return
    values from the underlying database or the operating system. (CVE-2020-3468)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-v78FubGV
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d85bb45b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs21296");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs21296");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3468");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
    {'min_ver': '0.0','fix_ver': '19.2.2.0'},
    {'min_ver': '20.0','fix_ver': '20.1.1'}
];

version_list=make_list(
  '19.2.099',
  '19.2.097'
);
 
reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvs21296',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting,
  vuln_versions:version_list
);
