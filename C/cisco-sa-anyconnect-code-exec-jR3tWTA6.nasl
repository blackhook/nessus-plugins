#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149448);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2021-1426",
    "CVE-2021-1427",
    "CVE-2021-1428",
    "CVE-2021-1429",
    "CVE-2021-1430",
    "CVE-2021-1496"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu77671");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv43102");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv60844");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw16996");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw17005");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw18527");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw18595");
  script_xref(name:"CISCO-SA", value:"cisco-sa-anyconnect-code-exec-jR3tWTA6");
  script_xref(name:"IAVA", value:"2021-A-0239-S");

  script_name(english:"Cisco AnyConnect Secure Mobility Client for Windows DLL and Executable Hijacking Vulnerabilities (cisco-sa-anyconnect-code-exec-jR3tWTA6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities in the install, uninstall, and upgrade processes of Cisco AnyConnect Secure Mobility Client 
for Windows could allow an authenticated, local attacker to hijack DLL or executable files that are used by the 
application. A successful exploit could allow the attacker to execute arbitrary code on an affected device with SYSTEM
privileges. To exploit these vulnerabilities, the attacker must have valid credentials on the Windows system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-code-exec-jR3tWTA6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7dd0d34b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu77671");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv43102");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv60844");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw16996");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw17005");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw18527");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw18595");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu77671, CSCvv43102, CSCvv60844, CSCvw16996,
CSCvw17005, CSCvw18527, CSCvw18595");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1496");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(378);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', win_local:TRUE);

var constraints = [
  {'fixed_version':'4.9.06037'},
  {'min_version': '4.10', 'fixed_version':'4.10.00093'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
