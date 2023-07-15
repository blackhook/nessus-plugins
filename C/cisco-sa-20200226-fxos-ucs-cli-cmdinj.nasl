#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134415);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3171");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42634");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-ucs-cli-cmdinj");
  script_xref(name:"IAVA", value:"2020-A-0085");

  script_name(english:"Cisco FXOS Software Local Management CLI Command Injection Vulnerability (cisco-sa-20200226-fxos-ucs-cli-cmdinj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a command injection vulnerability
within the local management (local-mgmt) CLI of Cisco FXOS Software due to insufficient input validation. An 
authenticated, local attacker can exploit this to execute arbitrary commands on the underlying operating 
system (OS) of an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-fxos-ucs-cli-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78c0d1d1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42634");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo42634.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3171");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('vcf.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

app_info = vcf::get_app_info(app:'FXOS');
product_info = make_array('model' , app_info['Model'], 'version' , app_info['version'], 'name', 'FXOS');

if(product_info['model'] !~ "^(41|93)[0-9]{2}$")
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.2.2.91'},
  {'min_ver' : '2.3',  'fix_ver': '2.3.1.144'},
  {'min_ver' : '2.4',  'fix_ver': '2.4.1.234'},
  {'min_ver' : '2.6',  'fix_ver': '2.6.1.187'},
  {'min_ver' : '2.7',  'fix_ver': '2.7.1.106'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo42634',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
