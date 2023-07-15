#TRUSTED 9ded2e41219aa4907f50b462f9b977839d4e933c58a9e326d51afb2866495f0df10ced601323a47356cc92a979bfd110350e976cf28f09779986cc08bb3343e2f616a005c8500bb7b75ceec69f976191bafc9ed7ffd922c5b3767165992c84143450a3c6cc0d1e8d8b197459927594f373bc35366bbea4cd2cdf943b3cc47b6986846aa4beb3da5bdd9385009bba87cb82f0af0077ea034ca4bc63800b377b0cc6a2dc13e1f22f0641b748072b10de06efc2d617938050de6b29bedbf587441bb15589c9e3d325eb5e9c75fb8d1dbbe8812d3d7a8c8f8c58c1230b5750fe010cc7028c3cb318ebb961f43b861c058e76d7d4ece4d162ef20e554732dc27030af3878a08277353e0dbe40761e8207fd40ad3fcfd580f394f5d030a0559280ad49f00388dfb0abc713e0b5aa33409d6e43ec1265a9a790dceb097f96f87e54343a3ce2c6d894be5a371fbe3fd5fad72b1a01f589c76378f6306b04c80e999140a00923b4c9e9892bfddc0b8ffe4cd8ff618299f6c090b52315f9cc694145dba8741f9b25dfb8e55e3b6e39422584da156637f83d357011301c77ee62ca3013e10c55a6b9ac6c92c63e0944bbaa99b4944c7097806492df0e2418fd37f65734a16b3c46bcd5527203bf20edfa789fb6564349bb4a93f2e0a3be41a6bd95ff29e7fa1363b3ee792dedadf1f8515b73b89e7876a1c478a44c6912455ae829d412b5ce
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161866);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/07");

  script_cve_id("CVE-2021-40114");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt57503");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx29001");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-dos-s2R7W9UU");

  script_name(english:"Cisco Firepower Threat Defense Snort Memory Leak DoS (cisco-sa-snort-dos-s2R7W9UU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a denial of service vulnerability. A denial 
of service (DoS) vulnerability exists in the way the Snort detection engine processes ICMP traffic. An unauthenticated,
remote attacker can exploit this issue by sending a series of ICMP packets which can cause the device to stop 
responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort-dos-s2R7W9UU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3be003ee");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt57503");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx29001");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40114");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(770);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.12'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.3'},
  {'min_ver': '6.7.0', 'fix_ver': '6.7.0.2'}
];

var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");

if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt57503, CSCvx29001',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
