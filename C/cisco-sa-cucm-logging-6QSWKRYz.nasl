#TRUSTED 13b75ca800c436cb48401ca1668a8d1edbd95a8e7daedadba13384b912ea56bdd9ff915c36c7f3d106ae65c368c790b1c4f54feb54534ff37126aa4d503033886bab0c66e09695ab03f72a5cb049f6d4e967563a4b20083e70e89acd8bc21898421cc20837c0d755d36d5ece32b24ab5a9d04e9f6fce27a1138787613768d2213ab01570821e6908c328cf55a2dc3390bd3a48542855fdf1282ac9330ebfe28368b2ab1f390d2ba1e45870de93288b7e3caf529704756655cd38251958cf2646e855ac130946e71ffe070e2b989bdfab5f0fd0188e843719ccd943f1d72d98c4523532d2f50624f18981fb24bb6983944994157ef0bf54147d10ad64674925f2fa5b478a0e303a888eb7993d4dd3a1d5153aa510db75bc8bf07dc50e0de671b239db69f756856267719eccadca6815a941deccdf55d854e833932abcba26323417205866ca35b9019f4779172507a29ed94940bcc914f4425a43e255c9c27f59fa09d03b80f9ee9fca204f114ee44f9344511c1a305b2f99a90fddbd237784ece7e6ba8ba726687a069aac7ec534d0b344619244218fe79a6eca8f6f34b9109f619b8548c041139c59cc075ed18664042c3ae8890294a0d855b8753c71bcca2f2045cd9aaf08851a947aaa7ad426e8d4fe82ac553f2661ed3a372bbc6ca749a5d3caa7a6565997c8f6b35b58f4930c9f7cf58c2833ccddbfe535d63e4165864b
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145263);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-1226");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu52881");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-logging-6QSWKRYz");
  script_xref(name:"IAVA", value:"2021-A-0028");

  script_name(english:"Cisco Unified CommunicationsManager Information Disclosure (cisco-sa-cucm-logging-6QSWKRYz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in Cisco Unified Communications Manager due to the storage of 
unencrypted credentials. An authenticated, remote attacker can exploit this, by accessing the audit logs of the
system, to disclose sensitive information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-logging-6QSWKRYz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b9a2d4f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu52881");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu52881");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1226");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(532);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# 11.5(1)SU9 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/11_5_1/SU9/cucm_b_release-notes-cucmimp-1151su9/cucm_m_about-this-release.html 
# 12.0(1)SU4 - https://jerome.pro/c/en/us/td/docs/voice_ip_comm/cucm/upgrade/12_0_1/cucm_b_upgrade-and-migration-guide-1201/cucm_b_upgrade-and-migration-guide-120_chapter_0101.html?referring_site=RE&pos=3&page=https://jerome.pro/c/en/us/td/docs/voice_ip_comm/cucm/upgrade/12_0_1/cucm_b_upgrade-and-migration-guide-1201/cucm_b_upgrade-and-migration-guide-120_chapter_0100.html
# 12.5(1)SU3 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/12_5_1/SU3/cucm_b_release-notes-for-cucm-imp-1251su3/cucm_m_about-this-release.html

vuln_ranges = [
  # No planned release for 10.5 so using it as min version for next fix version.
  { 'min_ver' : '10.5',  'fix_ver' : '11.5.1.21900.40' },
  { 'min_ver' : '12.0',  'fix_ver' : '12.0.1.24900.18' },
  { 'min_ver' : '12.5',  'fix_ver' : '12.5.1.13900.152'}
];

reporting = make_array(
  'port', 0,
  'severity', SECURITY_WARNING,
  'version', product_info['display_version'],
  'bug_id', 'CSCvu52881',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
