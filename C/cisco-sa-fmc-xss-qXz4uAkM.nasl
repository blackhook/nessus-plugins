##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161007);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id("CVE-2022-20627", "CVE-2022-20628", "CVE-2022-20629");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz24238");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz30558");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz30582");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fmc-xss-qXz4uAkM");
  script_xref(name:"IAVA", value:"2022-A-0184-S");

  script_name(english:"Cisco Firepower Management Center Software Cross-Site Scripting Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities in the web-based management interface of Cisco Firepower Management Center (FMC) Software 
could allow an authenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of the 
interface. These vulnerabilities are due to insufficient validation of user-supplied input by the web-based management
interface. An attacker could exploit these vulnerabilities by persuading a user of the interface to click a crafted 
link.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-xss-qXz4uAkM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?707c173f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz24238");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz30558");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz30582");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz24238, CSCvz30558, CSCvz30582");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20629");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');

vcf::check_granularity(app_info:app_info, sig_segments:3);
var constraints = [
  { 'min_version': '0.0', 'fixed_version' : '6.4.0.15'},
  { 'min_version': '6.5.0', 'fixed_version' : '6.6.5.2'},
  { 'min_version': '6.7.0', 'fixed_version' : '7.0.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
