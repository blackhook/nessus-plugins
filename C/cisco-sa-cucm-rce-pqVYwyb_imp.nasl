##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148970);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/23");

  script_cve_id("CVE-2021-1362");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv41616");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-rce-pqVYwyb");
  script_xref(name:"IAVA", value:"2021-A-0162");

  script_name(english:"Cisco Unified Communications Manager IM&P RCE (cisco-sa-cucm-rce-pqVYwyb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Communications Manager IM & Presence Service installed on the remote host is affected by a
remote code execution vulnerability due to improper sanitization of user-supplied input. An authenticated, remote
attacker can exploit this, by sending a SOAP API request with crafted parameters, in order to execute arbitrary code
with root privileges on the underlying operating system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-rce-pqVYwyb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c59ecd3a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv41616");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv41616.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1362");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_cucm_imp_detect.nbin");
  script_require_keys("installed_sw/Cisco Unified CM IM&P");

  exit(0);
}

include('vcf.inc');

var app = 'Cisco Unified CM IM&P';
get_kb_item_or_exit('installed_sw/' + app);

var app_info = vcf::get_app_info(app:app);

# 11.5(1)SU9 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/11_5_1/SU9/cucm_b_release-notes-cucmimp-1151su9/cucm_m_about-this-release.html
# 12.5(1)SU4 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/12_5_1/SU4/cucm_b_release-notes-for-cucm-imp-1251su4/cucm_m_about-this-release.html

var constraints = [
  { 'min_version' : '10.5.2', 'max_version': '10.5.2.9999999', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '11.0.1', 'max_version': '11.0.1.9999999', 'fixed_display' : '11.5(1)SU9' },
  { 'min_version' : '11.5.1', 'fixed_version' : '11.5.1.21900.5', 'fixed_display' : '11.5(1)SU9' },
  { 'min_version' : '12.0.1', 'max_version': '12.0.1.9999999', 'fixed_display' : '12.5(1)SU4' },
  { 'min_version' : '12.5.1', 'fixed_version': '12.5.1.14900.4', 'fixed_display' : '12.5(1)SU4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

