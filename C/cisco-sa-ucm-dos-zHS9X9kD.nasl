#TRUSTED 216e60374c0d0f11dadcf0d8cb937fb66de30ab0d91924612b0418da4cefe29f6cff38e67574029823d2931f0de18e7cb9918e15bec8a2e5a96db6157eeb0c0650b1f50c52f48688aaa7f056cafd670811ca3224e2ea01d36f1d5b825608f965916a372ac3ce7085b9799ea04982c40f76f122681bca0026b1f52427ffa419cdf71d9e2a975071a00c22da402d3ce16bec581005ab0472c3ac50e403daade46c3a4f5515123534e978cf896577ea54d9c42a09d5053d98d0b99678bffceb9fa2c5d6b64bf7229050cdd62bad4599013152c77ee0b378e3a07d0b2b8d99e7c9d3b864d39b8a7ad15c51e8ef4a90d7f08b7a776179acb6b9d02d09511a92189b66175ea0372cdde6c102e42bc303269c3a08012ff9caa7ce2e6e9de019dfc9d822fcbc06bf98452411754b1fd90928fad680c16b356c22dae3cc40711b9b3f414d509d61b55f29137737b8e86697a3cc96bf7c63b1f116ef84b02f0854d8b7dc13b8f7a00029ed0cd62a7867196a797b142aeb660f33c322b78ad24fe88142e70ca1c5b3299ea1cd1eaeaa5e5f5f736b050a65976eaf7d65b411788ed3ea16db428080b22d10733cb79666301209759940ac0a9209138e27d8b530dd3e418ec0d444cf3daf990f5d54a25e24d9282c9b81205846f5d41734d822e6a80e76e29245c2d5656fe8b49016fdb56b14ac1fd9cae5dae49ef668e05afa1537610598e5b5
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160316);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2022-20804");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy44822");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucm-dos-zHS9X9kD");
  script_xref(name:"IAVA", value:"2022-A-0178");

  script_name(english:"Cisco Unified Communications Products DoS (cisco-sa-ucm-dos-zHS9X9kD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Cisco Discovery Protocol of Cisco Unified Communications Manager (Unified CM) and Cisco Unified 
Communications Manager Session Management Edition (Unified CM SME) could allow an unauthenticated, adjacent attacker to 
cause a kernel panic on an affected system, resulting in a denial of service (DoS) condition. This vulnerability is due 
to incorrect processing of certain Cisco Discovery Protocol packets. An attacker could exploit this vulnerability by 
continuously sending certain Cisco Discovery Protocol packets to an affected device. A successful exploit could allow 
the attacker to cause a kernel panic on the system that is running the affected software, resulting in a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucm-dos-zHS9X9kD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4286b5cf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy44822");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy44822");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20804");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(754);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# 14SU1 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-14su1.html
var vuln_ranges = [{'min_ver' : '0', 'fix_ver' : '14.0.1.11900.132'}];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvy44822',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);