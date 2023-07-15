#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149467);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/17");

  script_cve_id("CVE-2021-1409");
  script_xref(name:"IAVA", value:"2021-A-0162");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw71918");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx14158");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx14178");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-xss-Q4PZcNzJ");

  script_name(english:"Cisco Unified Communications Manager IM & Presence Service XSS (cisco-sa-cucm-xss-Q4PZcNzJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Communications Manager IM & Presence Service installed on the remote host is prior to
version 14. It is, therefore, affected by a cross-site scripting vulnerability.

A vulnerability in the web-based management interface of Cisco Unified CM IM&P,could allow an unauthenticated, remote
attacker to conduct an XSS attack against an interface user. An attacker could exploit this vulnerability by persuading
an interface user to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script
code in the context of the affected interface or access sensitive browser-based information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-xss-Q4PZcNzJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e61edeb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw71918");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx14158");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx14178");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw71918, CSCvx14158, CSCvx14178");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1409");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
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
var app_info = vcf::get_app_info(app:app);

# https://software.cisco.com/download/home/286328299/type/282074312/release/14
var constraints = [  { 'fixed_version' : '14.0.1.10000.16' }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
