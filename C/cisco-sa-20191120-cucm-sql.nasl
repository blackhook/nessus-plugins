#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131739);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-15972");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp49463");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191120-cucm-sql");

  script_name(english:"Cisco Unified Communications Manager SQL Injection Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco Unified Communications Manager could allow an
authenticated, remote attacker to conduct SQL injection attacks on an affected system. The vulnerability exists because
the web-based management interface improperly validates SQL values. An attacker could exploit this vulnerability by
authenticating to the application and sending malicious requests to an affected system. A successful exploit could
allow the attacker to modify values on or return values from the underlying database.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191120-cucm-sql
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6526133f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp49463");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp49463");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15972");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

vuln_ranges = [
  {'min_ver' : '10.5', 'fix_ver' : '10.5.2.22186.1'},
  {'min_ver' : '11.5', 'fix_ver' : '11.5.1.17115.1'},
  {'min_ver' : '12.0', 'fix_ver' : '12.0.1.24051.1'},
  {'min_ver' : '12.5', 'fix_ver' : '12.5.1.12900.68'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp49463',
'sqli'     , TRUE
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
