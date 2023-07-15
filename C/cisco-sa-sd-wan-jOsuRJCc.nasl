#TRUSTED 200bf2399b547261b751d5ae425de441326edef9787d4854c3e68e96ed2d6275a0db99e54ab65e9c0df88abb4df2bd0d5af49360a8cf0a40d3709cb6f7eff4c890d8644b1f03d0dbedabc85a46494c03e6ea6054790fb8a2940112cf559e8c90b97ec4b77e0da54c5e12edd631e52cb160f5295bee3425c5f70fd2b78e4a41808e6985fc1b3b5439284c843cbd66dfbe91f569f3d030ce463c2ae7f6d979a0619c4ddaa7618c1f5c4d7faf0a1b4ee35c7976a11601f4b572846adaf752689b796724c9ac086d0984bb82dcf4524b8de8da67bbac4b51de376531a6fe0f1e3a73b388c56a29d9941988f338596bcb0504f56b7b1fbc55a0bc8bf393ee795193f2d000e0bd463dcdc030aa522185775555da80fa899f9ab80954805f1bbefa47e0ce367b38ca8b88d6296c3a815d05f6f77700e55c35ad31fc3cdbdb3bb8657084128c63b306c397359033bad133ea1bb9841a6ae26099e893a7d420413163a05846b6874b4bc4dd3cb0f4eb66eace52a8edce1b12aad7fe2df999e40f876018f23add04b0a47dd6fb509326f06ed60ce4a2b75868ead04455e29845f332076f52e65e63651227622d4862352559057dda2193a3c575797aeb738126a9573bafdae4b9f639ae36f1a39066127cb8273481b92977bd857ab86c5861addd664b80ef915972feaae672233955db513697b38464958051298379558748d737366d03c6
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153555);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/08");

  script_cve_id("CVE-2021-34712");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx45985");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-jOsuRJCc");
  script_xref(name:"IAVA", value:"2021-A-0435");

  script_name(english:"Cisco SD-WAN vManage Software Cypher Query Language Injection (cisco-sa-sd-wan-jOsuRJCc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco SD-WAN vManage Software could allow an
    authenticated, remote attacker to conduct cypher query language injection attacks on an affected system.
    This vulnerability is due to insufficient input validation by the web-based management interface. An
    attacker could exploit this vulnerability by sending crafted HTTP requests to the interface of an affected
    system. A successful exploit could allow the attacker to obtain sensitive information. (CVE-2021-34712)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-jOsuRJCc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7413ee7a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx45985");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx45985");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34712");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(943);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '18.4', 'fix_ver' : '20.3.4' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.2' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' },
  { 'min_ver' : '20.6', 'fix_ver' : '20.6.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvx45985',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
