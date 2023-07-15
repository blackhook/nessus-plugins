#TRUSTED 29cc9da4c7c7052f90acb8084d1cdffbc0f5224fa9871ffa331bc9fc627af4877a85b21cde0c0cddb0047fd70ac56c8e41603a72f89b9ea3fe714d6aa7d5b9bff44b8f8d994df0d498e73fba15a76510f3cad92d829ec45a0338642dfe84ad3e4844aa5d81ce166b187a36eabe24bd8030b1a4c8b28106d1f56680b8467a002162443674aa33fa88b9509fa5eed1b89dc85d27ea34c298cd3c73716292d30f490a9838953d1a67ffe063fa7ccd9f39349ea140defa02a9d282ea4987bac519b5c1dec72d0c5a1a2f87e50b060beba4d521d85f929d998dd018e1199cdbe42ae2ffb739f43c1befbbe69e559036f2b194350e1d60c2303d5b07437c9745685dbb956ce4cad2c33873f17ffcc794e63d9cbc1b3f669eb4db20bbad9a6b8c2b38550479cc9c8db732f86a35d429164e1c8b8b420ca56c6fba829c1878941fa5cd54fe6025bc97e123747e38901ab5f4b1b501cab666742eaee9ff2a40121cacba2fd8b6c16a0ed56695116c04a491a424f003526ab7b1a57c42e447eb0e6c8d9654bbb9bdf9d28a2477bfb7428a48037305d69494a9d831286860d43e3741abdb7b7c46e1532bfdefe41ccde4036050a43b9779eb4f8b7ed4908739501bf3d2ac6014dd6607630369a0ec68515eacec2fc8881e90eabff197681645fe013051aa39cba99a38b3f863c44b29409d076022071ac33715c28a39f29be617e97557b90b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147876);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_cve_id("CVE-2020-3379");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69987");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmpresc-SyzcS4kC");

  script_name(english:"Cisco SD-WAN Solution Software Privilege Escalation (cisco-sa-vmpresc-SyzcS4kC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Solution Software is affected by a privilege escalation 
vulnerability due to insufficient input validation. An authenticated, local attacker can exploit this by sending
a crafted request in order to gain administrative privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmpresc-SyzcS4kC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e017be1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69987");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi69987");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3379");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
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

if (tolower(product_info['model']) !~ "vbond|vedge|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0.0',  'fix_ver':'18.3.0' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69987',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
