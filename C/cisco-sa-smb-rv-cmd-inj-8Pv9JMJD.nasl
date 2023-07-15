#TRUSTED 61661e71a7364dd1ecda452bc609d0844bf04546a56a6f0415e8e843d36391f2f68ab7c217df9acd6410207e1bf1033be94bf8846f0a236a312676b00b2bdaf7f0328c01dbbfb168877ee97a95f811c4e0fe53c5c0b51a7314042cdc8b6fff7aea966f35cf82c49b92a8c492d136bdfbf60c961869c26cef23b22262e6c0af15686df7154e746cc3f38bf7b2773fc9819512727c2d6b7362a5b8add7afc170759437d4a9b3d3ec0bd391b91b84f609083170669af74c58d934a09355817b971db71ed591c8a7452391de8b8327f133cb17af8adfa57add2fdc150353805fde78ae26760f93dee9fd70e0c4981f0b8c7c995b8d3c32df9cfafabbde59fffcab1f463c25cf29cd3bd1143d720506bab1286e864e50b78aeb84e93eb5956b2849ae762b294161fa6b7cc7098de8825979fdd9f93ede5b94dcc640e6dee0a02f0e616fd1aa088534d31668e90778fe0965edfa5992aa0a76bdc94365878ac3f4c63a7cb9001be0a0e4dce5f1d6b95aa643557db6fe20de2cebe47ac94e4adc41e39a95fec6d50bf9b629bb28ad2508e1676e481fc1a78a2c5f85bee3840e47d5d1f6bbf706e88b6d34981373394d9cbee8ec5f27bd50c3662f74ea592b6bc497a67135326381345ecdad078d27904c59614478c91ae49da48dae6e63fa702ddab19a333569ceac023638b9e380a58ca72c5084c9e9a3ba9e1452c8545d1b3ab6c0d6
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161120);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2022-20799", "CVE-2022-20801");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa37678");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa59921");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa59943");
  script_xref(name:"CISCO-SA", value:"cisco-sa-smb-rv-cmd-inj-8Pv9JMJD");
  script_xref(name:"IAVA", value:"2022-A-0191");

  script_name(english:"Cisco Small Business RV Series Routers Command Injection Vulnerability (cisco-sa-smb-rv-cmd-inj-8Pv9JMJD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV340 and RV345 Routers could 
allow an authenticated, remote attacker to inject and execute arbitrary commands on the underlying operating system of 
an affected device. These vulnerabilities are due to insufficient validation of user-supplied input. An attacker could 
exploit these vulnerabilities by sending malicious input to an affected device. A successful exploit could allow the 
attacker to execute arbitrary commands on the underlying Linux operating system of the affected device. To exploit 
these vulnerabilities, an attacker would need to have valid Administrator credentials on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-smb-rv-cmd-inj-8Pv9JMJD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3fbcb25");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwa37678, CSCwa59921, CSCwa59943");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20801");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

# RV340 Dual WAN Gigabit VPN Routers
# RV340W Dual WAN Gigabit Wireless-AC VPN Routers
# RV345 Dual WAN Gigabit VPN Routers
# RV345P Dual WAN Gigabit POE VPN Routers

if (product_info['model'] !~ "^RV34(0W?|5P?)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');  

var vuln_ranges = [ { 'min_ver' : '0', 'fix_ver' : '1.0.03.27'} ];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwa37678, CSCwa59921, CSCwa59943',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
