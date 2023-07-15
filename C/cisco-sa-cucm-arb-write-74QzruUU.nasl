#TRUSTED 118232653275ddc09f43e188e525febc3ee0b91da877b3c178ad38b0821e3e15e73e8a5402ee00b44d1b057821ad07ec4d22385758d13b6287514b71ba6609cd841167a5312350dc38d374be4ad0f6aab6bb5fa88adfd4710cd34b872a9fa97f98c12c13588e1b46515578571728297249ec7ffed981648eca784336a0338a629f11854111f9e6b9061e3a1e67f272f7c978180f4e819e65fa435378f4d513f4438569e07f4ddcd78609e1b0958f26d9c9ff9c2d0386e9ea3729efba306edef0145ddc1c6f86533bbb0d2295bcfbd525c4cf0e2755516c4df279533c394cce07d0237112703b68faf14de3a0f6d64c3f25653e6ee6a284cadfe5adc537129461a7c390d215dea348dc9b61d10c301b5c59cb2d17d3be7ea7f24e97e14d6d1872971a4c975a15c4ce40dd121d59abf10da7216c509f49f8416459dd067645ccbd5b84a8a0ef556ade514b39326410df07e611c4dfd0b7ff83f469e5d883e2b4f4caa48d2eb32996238278283d767b8a03bb0682350b2eff663f406191b36f818f2195cd9f2856c2af1fba7fdcba7023e39ce359ed72935ec818d38c269750dd5d1e600a4a27bee65f0654a5dd4cc90e5d6f24a06d3dd15af7959c5568e6a9f20e0c63f8fffe74021ec1e7060d7910ecc45c092ef51760130eb31d422a83132a99570d207f19c62b6cdc4f8781cbf1ea6945dbbe3b3d32ef45743fc7960a73b787
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160336);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2022-20789");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy52032");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-arb-write-74QzruUU");
  script_xref(name:"IAVA", value:"2022-A-0178");

  script_name(english:"Cisco Unified Communications Products Arbitrary File Write (cisco-sa-cucm-arb-write-74QzruUU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the software upgrade process of Cisco Unified Communications
Manager (Unified CM) and Cisco Unified CM Session Management Edition is affected by an arbitrary file write
vulnerability. An authenticated remote attacker can exploit this vulnerability to write arbitrary files on the
affected system with root-level privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-arb-write-74QzruUU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e48ffbdb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy52032");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy52032");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20789");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(73);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

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

var vuln_ranges = [
    # 12.5(1)SU5 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/12_5_1/SU5/cucm_b_release-notes-for-cucm-imp-1251su5.html
    {'min_ver': '12.5.1', 'fix_ver': '12.5.1.15900.66'},
    # 14SU1 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-14su1.html
    {'min_ver': '14.0', 'fix_ver': '14.0.1.11900.132'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvy52032',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);

