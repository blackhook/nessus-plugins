#TRUSTED 1b7e437595ba0093f05f9a7cfccd2e8b12cf1557c1f52dd2b128068ed80abfd648e04885a85f37e6405b8801180135cc9d1b4589ba97a0c84655d11d0b3586f8e2c6ac72a002ef01e6a2c5202641a453bb35bd9409184a5b9e99e26fe3b292e7fd41ab3e97d9d76e7d6b6eb3d2e5d647b549512de625beb8f35bf9fd83de3c6d045fe89762f3d4d8577b89eba7cca8f7fe93301bc9993290253da114f729f43b20b11be9bb01768be49ae2311edfdf20216ece289f1702e238bf5c2fe590ee17d2cd91d268be34bcb40a97c6029a3202fb0ad0f0e0b3e200100c57dab233c394aa1e48cba747b406ab7687d57b089be9ef246aa76cf7a096bac22a98985d3d03ac198f9c65ab978a1c3aef1e9669e347bef9b008dcf2ad1c03503f579b5d831a460267ff37159950818b3d1106aee10d973bb8b6ecfc2c96a60a3f5e024d3556e55c7471092e4da618b1f610e9cff8f8b1b6d9881ce9275b5c70af45c617d94730e03a6313a353d5900fda3b1c000daff1756b4dfc0a4fa12ed4470df35d2996370e4a45c02baadd72da7d9f7715ba0c6d2887df6ebb1acdc94902e6f3936e0ba4001402e4c424e2c48d696e59a7daa8e22f6b4cc2ac637ec263dfbdf7dc1bed0c44dd5d8b61119903422a680dcfbdb07010cd0389c3f3c415d8702cf5626fd8c8e70118bcf1280c8dd187c46d945813ff138f876ebe159ae5ba86d2fee5fc88
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147760);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/16");

  script_cve_id("CVE-2020-3401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt74757");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmandowndir-CVGvdKM3");

  script_name(english:"Cisco SD-WAN vManage Software Path Traversal (cisco-sa-vmandowndir-CVGvdKM3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN vManage Software installed on the remote host is affected by a vulnerability as referenced
in the cisco-sa-vmandowndir-CVGvdKM3 advisory.

  - A vulnerability in the web-based management interface of Cisco SD-WAN vManage Software could allow an
    authenticated, remote attacker to conduct path traversal attacks and obtain read access to sensitive files
    on an affected system. The vulnerability is due to insufficient validation of HTTP requests. An attacker
    could exploit this vulnerability by sending a crafted HTTP request that contains directory traversal
    character sequences to the affected system. A successful exploit could allow the attacker to view
    arbitrary files on the affected system. (CVE-2020-3401)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmandowndir-CVGvdKM3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0db624c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt74757");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt74757");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3401");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22);

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
    {'min_ver': '0.0','fix_ver': '19.2.3.0'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt74757',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
