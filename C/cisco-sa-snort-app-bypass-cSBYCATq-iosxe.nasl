##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146211);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/12");

  script_cve_id("CVE-2021-1236");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu21318");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-app-bypass-cSBYCATq");
  script_xref(name:"IAVA", value:"2021-A-0026-S");

  script_name(english:"Cisco IOS XE Products Snort Application Detection Engine Policy Bypass (cisco-sa-snort-app-bypass-cSBYCATq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE is affected by a vulnerability in the UTD SNORT 
IPS detection engine due to a flaw in the detection algorithm. An unauthenticated, remote attacker can exploit this by 
sending crafted packets that would flow through an affected system. A successful exploit could allow the attacker to 
bypass the configured policies and deliver a malicious payload to the protected network.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort-app-bypass-cSBYCATq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5c32102");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu21318");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1236");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(670);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Affects Cisco ISR1000, ISR4000, ISA3000, CSR1000V
model = toupper(product_info['model']);
if(!pgrep(pattern:"ISR[14]0{3}|ISA30{3}|CSR10{3}V", string:model))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '17.4.1' }];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['utd_enabled'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu21318',
  'cmds'     , make_list('show utd engine standard status')
);

cisco::check_and_report(
  product_info      : product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_ranges       : vuln_ranges
);
