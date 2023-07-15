#TRUSTED 49ee31bc5c12bf5f40f965827d72da1cad9f873c492100d99685a737f87f1ad812cfa62d4fa8b17c3fbbb4f87ca419d7af4b9e125d623dd593d617aa1bb3dfbbd213483867e17d9a27ec7224d58d7858eb6ed3fd3a52be495c36c87f35b0e078cf5e12645747bd4309dd09c24d0db688fd6fb14e28d58aeb616fc14efb885fbbdce9bee146b8263f89626624d4bc59030517675b3107a7c2e6428607aa0fc269ac7e3cbcb5e90c63d0d39302d7e7a9c0df3a4e6851cdbb32ee6b61b6e02ced83d0b8692d2e9e570c2cd7ca675d0092094b18959b8ed812461ef4f53b3f6a4d618fa56e5c21915216739f9b8e62e5d1458f2cbeadce14cc042707ac5c61871152f3d19719a3296860af70fd3f7aa97107fa6e59a5518460e73fb66b2dfe573372379931fa00085f52a4ad3246436a0118b0d405b740243348352f430608a49c7a45394dc1982382fc3f7d048bc4d33f77d3ef8e844b79b89b5756a45b39d20a93a821f3cb678caafdcdc8e85c89f7871fae6be39fa02c48690dc87b811f26f71a9f7065cdbd6bf01d3a4d8d27f0e8b0c38f4ca6dc5059187960195a8cd58f7f9d2e65eeabad6a7a7d49541db2881071a1a51bc554bdb503011d1c6eb3a0b0f61b048acadffc6662217ba8c28558dd2ce48dd4ab48752b8bdc09f6bbfd08af255d06846e822b23876d15907b89efcd5d66f1dd22ed3f26442cc0e3056191ca83d9
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142995);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2020-3594");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv42376");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vepestd-8C3J9Vc");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN Software Privilege Escalation (cisco-sa-vepestd-8C3J9Vc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN is affected by a privilege escalation vulnerability exists due to
insufficient input validation. An authenticated, local attacker can exploit this by sending crafted options to a specific
command, to gain root access to the system.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vepestd-8C3J9Vc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2217d3c3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv42376");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv42376");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3594");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/18");

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

if (tolower(product_info['model']) !~ "vbond|vedge|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0.0',  'fix_ver':'20.1.2' },
  { 'min_ver':'20.3',  'fix_ver':'20.3.2' }
];

# 20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv42376',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
); 
