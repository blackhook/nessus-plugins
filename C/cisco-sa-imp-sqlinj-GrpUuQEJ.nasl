#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160376);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2022-20786");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy16643");
  script_xref(name:"CISCO-SA", value:"cisco-sa-imp-sqlinj-GrpUuQEJ");

  script_name(english:"Cisco Unified Communications Manager IM & Presence Service SQLI (cisco-sa-imp-sqlinj-GrpUuQEJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco Unified Communications Manager IM Presence Service 
(Unified CM IMP) could allow an authenticated, remote attacker to conduct SQL injection attacks on an affected system. 
This vulnerability is due to improper validation of user-submitted parameters. An attacker could exploit this 
vulnerability by authenticating to the application and sending malicious requests to an affected system. A successful 
exploit could allow the attacker to obtain data or modify data that is stored in the underlying database of the 
affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-imp-sqlinj-GrpUuQEJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2f5f43a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy16643");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy16643");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_cucm_imp_detect.nbin");
  script_require_keys("installed_sw/Cisco Unified CM IM&P");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco Unified CM IM&P');

# 11.5(1)SU11 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/11_5_1/SU9/cucm_b_release-notes-cucmimp-1151su9/cucm_m_about-this-release.html
# 12.5(1)SU6 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/12_5_1/SU6/cucm_b_release-notes-for-cucm-imp-1251su6.html
# 14SU1 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/14_0_1/SU1/cucm_b_release-notes-for-cucm-imp-14su1.html
var constraints = [
  { 'min_version' : '11.5.1', 'fixed_version' : '11.5.1.23900.3', 'fixed_display' : '11.5(1)SU11' },
  { 'min_version' : '12.5.1', 'fixed_version': '12.5.1.16900.3', 'fixed_display' : '12.5(1)SU6' },
  { 'min_version' : '14.0.1', 'fixed_version': '14.0.1.11900.9', 'fixed_display' : '14SU1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);