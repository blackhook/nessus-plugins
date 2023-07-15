#TRUSTED acf704b7a26aeb2fae12340a1b301cf122a89caf1999a0f237f415758ab53f010a38694b88812b520ef1042a5e1541f1e8e4e6224e64c97e881efae001b2b775e967e75757fa16fa7b064441fc26fc77eb8ff7f8344e9141baa05e8b36d2094b9b5a1f11768bf32d2db99159d5ba31946c819421eb9db195b7f04530ee28bb95894b6ed8942f2cfdbfa132bc407548b6b2f46aee765f7e9e24be70c0625239f15e57d80cee4cb90307215254fd8333cf4b6f335578ba641fa43615cc0ab96bf513b0b1c4b0467a6379d46b946c0a5ffb5c8e6e25267046701e81a740a5e1b0e4107b87d73969c40ea626ba7a95b12b0bafa378125ea3cbf3dcec54cd1809cc38de913519064c6b729608b95d20d713c027f95d8f1206a8a208683206206a830a6c1cdf58c57ed807a5167f3892fffd2611e6ad96c3f668bce99a3ad1c29ebf857fcc767fe0bb29a9fafa4c07e29994b77e2c080253010d46bee8358b0822d7bad4c71d452796ef78e0416de4fd3f312a2da329aaf207d79ab669d9fe37b5a9599f808700cf22c230b0f6048492487f95414038406105f30e0c6b1ea499455da539fc58dc2e400312b98deb284ce26cf8ba18e1b70ca80ddc3c11c96c331f0af64569ad1c3911feb9af2bc8b0199146ce8e45d41c6d1eae0ced6ca2c95a4c23f7c80f551e9d48b6180af0e04c602284377eda6c4c73f3d18aa26ee8a44404987c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131427);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq64435");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190821-iosxe-ngwc-csrf");
  script_xref(name:"IAVA", value:"2019-A-0316");

  script_name(english:"Cisco IOS XE NGWC Legacy Wireless Device Manager GUI CSRF Vulnerability (cisco-sa-20190821-iosxe-ngwc-csrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a CSRF vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the web-based
management interface of Cisco IOS XE New Generation Wireless Controller (NGWC) which allow an unauthenticated, remote
attacker to conduct a cross-site request forgery (CSRF) attack and perform arbitrary actions on an affected device.
The vulnerability is due to insufficient CSRF protections for the web-based management interface of the affected
software. An attacker could exploit this vulnerability by persuading a user of the interface to follow a crafted link.
A successful exploit could allow the attacker to perform arbitrary actions on an affected device by using a web browser
and with the privileges of the user.

Please see the included Cisco BID(s) and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190821-iosxe-ngwc-csrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8af6c2cc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq64435");
  script_set_attribute(attribute:"solution", value:
"No fix available. Please refer to Cisco bug ID CSCvq64435");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12624");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = get_kb_item_or_exit('Host/Cisco/IOS-XE/Model');
device_model = get_kb_item('Host/Cisco/device_model');

# Affected models:
# Cisco Catalyst 4500E Supervisor Engine 8-E (Wireless) Switches
# 5760 Wireless LAN Controllers
# Catalyst 3650 Series Switches
# Catalyst 3850 Series Switches
vuln = FALSE;
show_ver = get_kb_item("Host/Cisco/show_ver");
if (device_model =~ "cat" &&
    ((product_info.model =~ "([^0-9]|^)45[0-9]{2}E" && "WS-X45-SUP8-E" >< show_ver) ||
    product_info.model =~ "([^0-9]|^)3[68][0-9]{2}")
   )
  vuln = TRUE;
# In a previous advisory example (cisco-sa-20170927-ngwc), 5760 has 5700 so just look for 57xx.
# On Software Downloads page, 5760 is the only 5700 Series WLC
else if (product_info.model =~ "([^0-9]|^)57[0-9]{2} Series Wireless LAN Controller")
  vuln = TRUE;

if (!vuln || 'e' >!< tolower(product_info.version))
  audit(AUDIT_HOST_NOT, "affected");

vuln_ranges = [
  {'min_ver' : '3.0', 'fix_ver' : '4.0'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info.version,
  'bug_id'   , 'CSCvq64435',
  'fix'      , 'No known fix, refer to Cisco advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
