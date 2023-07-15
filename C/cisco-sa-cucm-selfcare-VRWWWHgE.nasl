#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148643);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-1399");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw88205");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-selfcare-VRWWWHgE");
  script_xref(name:"IAVA", value:"2021-A-0162");

  script_name(english:"Cisco Unified Communications Manager Self Care Portal Authorization Bypass Vulnerability (cisco-sa-cucm-selfcare-VRWWWHgE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Self Care Portal of Cisco Unified Communications Manager (Unified CM) and 
Cisco Unified Communications Manager Session Management Edition (Unified CM SME) is affected by authorization bypass 
vulnerability due to insufficient validation of user-supplied data to the Self Care Portal. An authenticated, remote 
attacker can exploit this by sending a crafted HTTP request to an affected system. A successful exploit could allow the 
attacker to modify information without proper authorization.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-selfcare-VRWWWHgE
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?39dce611");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw88205");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw88205");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1399");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(302);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

# 12.5(1)SU4 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/12_5_1/SU4/cucm_b_release-notes-for-cucm-imp-1251su4.pdf

vuln_ranges = [{ 'min_ver' : '10.5',  'fix_ver' : '12.5.1.14900.63'}];

reporting = make_array(
  'port', 0,
  'severity', SECURITY_WARNING,
  'version', product_info['display_version'],
  'bug_id', 'CSCvw88205',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
