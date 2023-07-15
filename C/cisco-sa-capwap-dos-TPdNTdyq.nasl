##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145692);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id(
    "CVE-2020-3486",
    "CVE-2020-3487",
    "CVE-2020-3488",
    "CVE-2020-3489",
    "CVE-2020-3493",
    "CVE-2020-3494",
    "CVE-2020-3497"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr51353");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr52613");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr76792");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr77049");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr77764");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr84445");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr91229");
  script_xref(name:"CISCO-SA", value:"cisco-sa-capwap-dos-TPdNTdyq");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family CAPWAP DoS (cisco-sa-capwap-dos-TPdNTdyq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software for Cisco Catalyst 9800 Series Wireless Controllers, 
Catalyst 9300, 9400, and 9500 Series Switches, and Catalyst 9100 Access Points are affected by multiple denial of 
service (DoS) vulnerabilities due to insufficient validation of CAPWAP packets. An unauthenticated, adjacent attacker
could exploit these vulnerabilities by sending a malformed CAPWAP packet to an affected device. A successful exploit 
could allow the attacker to cause the affected device to cause a crash and reload of the device, resulting in a DoS 
condition on the affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-capwap-dos-TPdNTdyq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f82c71be");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr51353");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr52613");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr76792");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr77049");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr77764");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr84445");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr91229");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr51353, CSCvr52613, CSCvr76792, CSCvr77049, 
CSCvr77764, CSCvr84445, CSCvr91229");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3486");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Host/Cisco/device_model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects Cisco Catalyst 9100, 9300, 9400, 9500, 9800
if ('cat' >!< tolower(device_model) || model !~ '9[13458][0-9][0-9]') audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1c',
  '16.10.1e',
  '16.10.1d',
  '16.10.2',
  '16.10.1f',
  '16.10.1g',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.1w',
  '16.12.2',
  '16.12.1y',
  '16.12.2a',
  '16.12.3',
  '16.12.2s',
  '16.12.1x',
  '16.12.1t',
  '16.12.2t',
  '16.12.3a',
  '17.1.1',
  '17.1.1a',
  '17.2.1t',
  '17.2.1v'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr51353, CSCvr52613, CSCvr76792, CSCvr77049, CSCvr77764, CSCvr84445, CSCvr91229',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions
);
