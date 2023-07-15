#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169768);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/16");

  script_cve_id("CVE-2020-3447");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu44277");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu44286");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-log-YxQ6g2kG");
  script_xref(name:"IAVA", value:"2020-A-0218-S");

  script_name(english:"Cisco Content Security Management Appliance Information Disclosure (cisco-sa-esa-sma-log-YxQ6g2kG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the host is affected by a vulnerability in the CLI of Cisco AsyncOS for Cisco
Content Security Management Appliance (SMA) that could allow an authenticated, remote attacker to access sensitive 
information on an affected device. The vulnerability is due to excessive verbosity in certain log subscriptions. An
attacker could exploit this vulnerability by accessing specific log files on an affected device. A successful exploit 
could allow the attacker to obtain sensitive log data, which may include user credentials. To exploit this vulnerability
, the attacker would need to have valid credentials at the operator level or higher on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-log-YxQ6g2kG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8d51c52");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu44277");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu44286");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu44277, CSCvu44286");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3447");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:secure_email_and_web_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '13.6.1.201' }];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvu44277, CSCvu44286',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
