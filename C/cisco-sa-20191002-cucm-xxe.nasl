#TRUSTED 8592ebefda1e807223fcc41521202aebb9c6dd4bb38df7ffd2de8d90f41e5835fd29381bb0771a96d5b74e7a4d967d112fed3ee2762ebdeeb6a47839458b586e7c0722960fa51c24cd0ac296cbf69fd4141a1ee3d506b782e90889d5cfa9dd880f7b7a9d3cf747fc87f38df28748e675299f709e0506fa60bfd20e27db3a833f0cac958a39dbfcbd6b5bf6781ee0de6fca99de07953420f58172ce7151430b7f121a19ecc23ca0bdb5de06c1c96ccf9f5dae756ed52e14c26ceb5e0b67bf4b8cc36cb6a47cdb1f4f6177371cee57bea95bdec805c87aeba08a1fed2169bd41649ad37855fedc515e985a3355f143a2d839158b115dcb31d570e9a079a53f99ed5b1618fd97751c6d6f1605d4cefc3671cffd225e26ec6db6c896446b0eebdd877abdc9a63645fe51200737ae1302f12f2d66b7b01c39b8bc96b751e16d29975878b1f25723d7a51e9ff1d0d1219d5ef9d9ed6d67feaf0980df9e4e5d72a775edf2c4ba1a172ca099fc2ef64b432f17588bf257a200a7f850cf14c09a4d92a75478a79646bce60ba0197a905aff143110aaaa707950b42e6eeff17f6a370f686e256151e47710ced0f3101bce7e99a68e08363cae5b771b88036d77bb6347e507d97cd319a3353226769ccf367584b0d5cda11aed6945c5950e71961343c85ab17264cf875ae2231218e1b4972948cb65c785feabfafee293128eb4e8b53ca620
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135897);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-12711");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp46079");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-cucm-xxe");
  script_xref(name:"IAVA", value:"2019-A-0362");

  script_name(english:"Cisco Unified Communications Manager XML External Expansion Vulnerability (cisco-sa-20191002-cucm-xxe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager is affected by an XML external entity
(XXE) vulnerability. This is due to an incorrectly configured XML parser accepting XML external entities from an untrusted
source. An unauthenticated, remote attacker can exploit this, via specially crafted XML data, to disclose sensitive
information, or cause the application to consume available resources which would result in Denial of Service.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-cucm-xxe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?421420ec");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp46079
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?389f5230");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp46079");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12711");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(611);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '10.5.2.21900.13'},
  # 11.5 version number taken from ReadMe for 11.5(1)SU7 ; https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-1151su7.html  
  # Advisory and BID are very unclear, stating 11.5(1)SU5 and earlier are vulnerable
  # 11.5(1)SU6 was removed from fixed versions, implying that 11.5(1)SU7 is the fix
  {'min_ver' : '11.5', 'fix_ver' : '11.5.1.17900.52'}, # 11.5(1)SU5
  {'min_ver' : '12.0', 'fix_ver' : '12.0.1.23900.9'},
  {'min_ver' : '12.5', 'fix_ver' : '12.5.1.11900.146'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp46079'
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
