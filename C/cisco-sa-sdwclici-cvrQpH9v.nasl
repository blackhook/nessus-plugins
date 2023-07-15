#TRUSTED 173a65401c17ba4beb3b62f3be8060eb9515aad33ff948ad8f40e158fa52b12f610980e7bd61c2dc98487424ea920ae58426243c1bf40a514bf1a036e40d5489d3ea4140e673c1e57a052a9d11ccef5215e3a41f6874ae92a0f8cfec12a2f2fd6308e0edc77d92e2a86a7be525d4db696faa93a02ad39905487eaf8d99eec65980891cb4c1de92774627849585afc13f2e43100f0a2aa9158858ca72d0ce03486d169061973c1d4e7265274fb96fea016c134e01bd158c6d82ef819336e97a34b5301ce192da46a2173c815725c4a51e243986980133b63d7f4c231880c37f8d18e93681151dccc978b5cf19610cb117bc3cbae76767b3904e4559fe5cc1b8c63cd3fd55dd792b6c90cf808e02994b21abf740b33c3a489c137309d748fe243df0d432240167faacb8de19317e3a72f3ccaf5af855e632dbf10ee1ed565ce4d0d5848bc7839ae50e757926bdfed3b88946fefc32a840a4eaf595d50a73a27330b60eeb2f1a507ee4e80271b2db96e524504b849bd7952782a5a7e58968856acb33e3c25965ae473fa0b2deaa986840722957b1527140e06f4eb99d23bbb5cfa693712a476a72028de5bec40a60b1c2809fc61f422dec70cace9795abc68d53c8886a0b75acfd84a44890fdc08f0d41673c9c538473d9938d28559a1bf6b7face3dfadec4d75bf9c0ef6a78526777b2a7ed40736d110846360e6eb03ddd4dcf94
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147733);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3266");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs47126");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwclici-cvrQpH9v");

  script_name(english:"Cisco SD-WAN Solution Command Injection (cisco-sa-sdwclici-cvrQpH9v)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Solution is affected by a command injection vulnerability due to
insufficient input validation. An authenticated, local attacker can exploit this, by authenticating to the device and
submitting crafted input to the CLI utility, in order to inject arbitrary commands.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwclici-cvrQpH9v
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cb97617");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs47126");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs47126");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3266");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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
  { 'min_ver':'0', 'fix_ver':'19.2.2' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs47126',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
