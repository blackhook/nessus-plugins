##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146213);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2021-1355", "CVE-2021-1357", "CVE-2021-1364");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv20974");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv20985");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv62648");
  script_xref(name:"CISCO-SA", value:"cisco-sa-imp-trav-inj-dM687ZD6");
  script_xref(name:"IAVA", value:"2021-A-0028");

  script_name(english:"Cisco Unified Communications Products Vulnerabilities (cisco-sa-imp-trav-inj-dM687ZD6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, multiple vulnerabilities in Cisco Unified Communications Manager IM & Presence 
Service (Unified CM IM&P) could allow an attacker to conduct path traversal attacks and SQL injection attacks on an 
affected system. One of the SQL injection vulnerabilities that affects Unified CM IM&P also affects Cisco Unified 
Communications Manager (Unified CM) and Cisco Unified Communications Manager Session Management Edition (Unified CM SME) 
and could allow an attacker to conduct SQL injection attacks on an affected system. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-imp-trav-inj-dM687ZD6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7810b2b4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv20974, CSCvv20985, CSCvv62648");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1364");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1357");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(35, 89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_presence_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_cucm_imp_detect.nbin");
  script_require_keys("installed_sw/Cisco Unified CM IM&P");

  exit(0);
}

include('vcf.inc');

app = 'Cisco Unified CM IM&P';
get_kb_item_or_exit('installed_sw/' + app);

app_info = vcf::get_app_info(app:app);

# 11.5(1)SU9 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/11_5_1/SU9/cucm_b_release-notes-cucmimp-1151su9/cucm_m_about-this-release.html 
# 12.5(1)SU4 - advisory still not available  (March 2021) used the version in the bugid

constraints = [
  { 'min_version' : '12.0', 'max_version': '12.5.1.13000.163', 'fixed_version' : '12.5.1.13000.164', 'fixed_display' : '12.5(1)SU4' },
  { 'min_version' : '11.5', 'max_version': '11.5.1.21900.4', 'fixed_version' : '11.5.1.21900.5', 'fixed_display' : '11.5(1)SU9' },
  { 'min_version' : '0.0', 'max_version': '11.5', 'fixed_display' : 'Please see advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
