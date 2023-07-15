#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171792);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/13");

  script_cve_id("CVE-2023-20009");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd29901");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-privesc-9DVkFpJ8");
  script_xref(name:"IAVA", value:"2023-A-0107");

  script_name(english:"Cisco Email Security Appliance PrivEsc (cisco-sa-esa-sma-privesc-9DVkFpJ8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance is affected by a vulnerability in the web UI 
and CLI of Cisco ESA could allow an authenticated, remote attacker (web UI) or authenticated, local attacker (CLI) to 
elevate privileges to root. The attacker must have valid user credentials with Operator-level privileges or higher. 
This vulnerability is due to the improper validation of an uploaded Simple Network Management Protocol (SNMP) 
configuration file. An attacker could exploit this vulnerability by authenticating to the affected device and uploading
a specially crafted SNMP configuration file. A successful exploit could allow the attacker to execute commands as root. 
  
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-privesc-9DVkFpJ8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93abb59b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd29901");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd29901");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20009");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

# We cannot test for LDAP or external authentication
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '12.5.4.041'},
  { 'min_ver' : '13.0', 'fix_ver' : '13.0.5.007' },
  { 'min_ver' : '13.5', 'fix_ver' : '13.5.4.038' },
  { 'min_ver' : '14.0', 'fix_ver' : '14.2.1.020' }
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd29901',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
