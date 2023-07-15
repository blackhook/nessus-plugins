#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146214);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_cve_id("CVE-2021-1282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv62642");
  script_xref(name:"CISCO-SA", value:"cisco-sa-imp-trav-inj-dM687ZD6");
  script_xref(name:"IAVA", value:"2021-A-0028");

  script_name(english:"Cisco Unified Communications Products Vulnerabilities (cisco-sa-imp-trav-inj-dM687ZD6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a SQL injection (SQLi) vulnerability exists in the web-based management 
interface of Cisco Unified CM and Cisco Unified CM SME due to improper validation of user-submitted parameters.
An authenticated, remote attacker with administrative credentials can exploit this to conduct SQL injection attacks 
on an affected system. A successful exploit could allow the attacker to obtain data that is stored in the underlying 
database.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-imp-trav-inj-dM687ZD6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7810b2b4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv62642");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1282");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(35, 89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

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
# 12.0(1)SU4 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/upgrade/12_0_1/cucm_b_upgrade-and-migration-guide-1201/cucm_b_upgrade-and-migration-guide-120_chapter_0101.html?referring_site=RE&pos=3&page=https://jerome.pro/c/en/us/td/docs/voice_ip_comm/cucm/upgrade/12_0_1/cucm_b_upgrade-and-migration-guide-1201/cucm_b_upgrade-and-migration-guide-120_chapter_0100.html
# 12.5(1)SU4 - advisory still not available  (March 2021) got the version on the bugid

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '11.5.1.21900.40' },
  { 'min_ver' : '12.0', 'fix_ver' : '12.0.1.24900.18' },
  { 'min_ver' : '12.5', 'fix_ver' : '12.5.1.14600.33' }
];

reporting = make_array(
  'port', 0,
  'severity', SECURITY_WARNING,
  'version', product_info['version'],
  'bug_id', 'CSCvv62642',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
