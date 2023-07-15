#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154931);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/09");

  script_cve_id("CVE-2021-34701");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy89690");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-path-trav-dKCvktvO");

  script_name(english:"Cisco Unified Communications Manager IM & Presence Service Path Traversal (cisco-sa-cucm-path-trav-dKCvktvO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Communications Manager IM & Presence Service (Unified CM IM&P) installed on the remote
host is prior to 14SU1. It is, therefore, affected by a path traversal vulnerability in the web-based management
interface that allows an authenticated, remote attacker to access sensitive data. This is caused by improperly
validated data.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-path-trav-dKCvktvO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d746fdc8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy89690");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy89690");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34701");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
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

var app_info = vcf::get_app_info(app:app);

# 14SU1 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/14_0_1/SU1/cucm_b_release-notes-for-cucm-imp-14su1.html
var constraints = [
  { 'fixed_version': '14.0.1.11900.9', 'fixed_display' : '14SU1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

