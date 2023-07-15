##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162981);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/11");

  script_cve_id("CVE-2022-20800");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz33979");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-xss-RgH7MpKA");
  script_xref(name:"IAVA", value:"2022-A-0266");

  script_name(english:"Cisco Unified Communications Manager IM & Presence XSS (cisco-sa-cucm-xss-RgH7MpKA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Communications Manager IM & Presence Service on the remote host is 12.5(1) prior to
12.5(1)SU5. It is, therefore affected by a cross-site scripting vulnerability (XSS). An unauthenticated remote
attacker could, with the interaction of another user, exploit this vulnerability to execute arbitrary code in the
context of the affected interface or access sensitive browser-based information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-xss-RgH7MpKA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?927bff4c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz33979");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz33979");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

var constraints = [
  # https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/12_5_1/SU5/cucm_b_release-notes-for-cucm-imp-1251su5.html
  {'min_version': '11.5.1', 'fixed_version': '12.5.1.15900.5', 'fixed_display': '12.5(1)SU5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
