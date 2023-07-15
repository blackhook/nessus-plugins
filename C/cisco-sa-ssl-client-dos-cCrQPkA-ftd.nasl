#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178101);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-20927");
  script_xref(name:"IAVA", value:"2022-A-0486");
  script_xref(name:"IAVA", value:"2022-A-0487");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz98540");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ssl-client-dos-cCrQPkA");

  script_name(english:"Cisco Firepower Threat Defense Software SSL/TLS Client DoS (cisco-sa-ssl-client-dos-cCrQPkA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense (FTD) Software is affected by a denial of 
service (DoS) vulnerability in the Secure Sockets Layer (SSL)/Transport Layer Security (TLS) handler of Cisco FTD 
Software. This vulnerability is due to improper memory management when a device initiates SSL/TLS connections. 
An attacker could exploit this vulnerability by ensuring that the device will connect to an SSL/TLS server that is 
using specific encryption parameters. A successful exploit could allow the attacker to cause the affected device 
to unexpectedly reload, resulting in a DoS condition.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ssl-client-dos-cCrQPkA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99193417");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74838");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz98540");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20927");

  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
var model = product_info['model'];
var vuln_versions = NULL;

// Cisco Firepower 4100, 9300 Series
if (model =~ "(FPR-?|Firepower)\s*(41[0-9]{2}|4K|93[0-9]{2}|9K)")
{
  vuln_versions = make_list(
    '6.5.0',
    '6.5.0.1',
    '6.5.0.2',
    '6.5.0.3',
    '6.5.0.4',
    '6.5.0.5',
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3'
  );
}
// Cisco ASA 5500-X Series Firewalls
else if (model =~ "ASA55[0-9]{2}-X")
{
  vuln_versions = make_list(
    '6.5.0',
    '6.5.0.1',
    '6.5.0.2',
    '6.5.0.3',
    '6.5.0.4',
    '6.5.0.5',
    '6.6.0',
    '6.6.0.1',
    '6.6.1',
    '6.6.3',
    '6.6.4',
    '6.6.5',
    '6.6.5.1',
    '6.6.5.2',
    '6.7.0',
    '6.7.0.1',
    '6.7.0.2',
    '6.7.0.3'
  );
}
else audit(AUDIT_HOST_NOT, 'an affected model');

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvz98540',
  'fix'      , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions
);
