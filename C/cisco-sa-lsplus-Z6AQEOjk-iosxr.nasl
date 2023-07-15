#TRUSTED 70a5cf8892bdef5fd0cb0b6c3ab7b40589c9ba5842a05a8bd3ec17d39b664e8a72a056581e0dfe06b9425a36f8c794557066cb7a95d1893cd8e2518a83445e2af53ae8283c06169d42f9f1245b03ce132e36cae1627b5517f57da9015a1231d08fa4599c9bcd7f321708e87c52674850c093c0c839b2769febf49e6e1307218dc74dab6235134501882bbbcf3edf3fd04d9789d10440eae575f4d363a2e06aca5bf0484f3347f5ca6e530fdf7b38a02918bea4f7f847f09c0d487d271e54e9c4830f07463480ae0e3382bfbe2d1e5c14565892b3e2ff656fe2a73d90208796fb56914ce490ccef8baabd38c2ca33a63b52ed089b077117c585c4e743816bb6e4e95488cbe683908acd62af352a0b0493b989ea7b185341d04fe06917b9596fbf08e2629fe520eeb82242e3e4a0091bac6ea04c3c3296c05fb05b5ae70f7b00e3c8ddbb6a69be397362eeeaf4e9bee2f8e3acc8d9018505a4dfd8b4c8e1c0122bd4430daff3945fc1e04f36217a65b8e4f229077985a23d9f4f734cc67dab009e1d769f1624103cf8389595723c0bf862134e948c10a3926c85bceda13eacafbad837d912c8be6fca39641a387f0385a446cdc371a417a75658f0b49ee256884742eb80256450abcadc71dbf2a485ac6dcd32d504c091fac21749c91b85c8319761db4c1fd1f190526b3e1da42aaeeac6ca60762f410e617172605502bed7ec16
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160086);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2022-20714");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy48962");
  script_xref(name:"CISCO-SA", value:"cisco-sa-lsplus-Z6AQEOjk");
  script_xref(name:"IAVA", value:"2022-A-0173");

  script_name(english:"Cisco IOS XR Software for ASR 9000 Series Routers Lightspeed Plus Line Cards DoS (cisco-sa-lsplus-Z6AQEOjk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by denial of service vulnerability due to a 
vulnerability in the data plane microcode of Lightspeed-Plus line cards that cause the line card to reset. An 
unauthenticated, remote attacker can exploit these by sending a specific IPv4 or IPv6 packet through an affected 
device. A successful exploit could allow the attacker to cause the affected line card to reset.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lsplus-Z6AQEOjk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c2f5ce1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74835");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy48962");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy48962");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(126);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);

# Vulnerable model list
if ('ASR9K' >< model)
    audit(AUDIT_HOST_NOT, 'affected');

var card_list = make_list(
  'A9K-4HG-FLEX-SE',
  'A9K-4HG-FLEX-TR',
  'A9K-8HG-FLEX-SE',
  'A9K-8HG-FLEX-TR',
  'A9K-20HG-FLEX-SE',
  'A9K-20HG-FLEX-TR',
  'A99-4HG-FLEX-SE',
  'A99-4HG-FLEX-TR',
  'A99-10X400GE-X-SE',
  'A99-10X400GE-X-TR',
  'A99-32X100GE-X-SE',
  'A99-32X100GE-X-TR'
);

var l_card = cisco_line_card(card_list:card_list);

if (empty_or_null(l_card))
  audit(AUDIT_HOST_NOT, 'an affected line card');

var smus = [];
if ('ASR9K' >< model)
{
    smus['7.1.2'] = 'CSCvy48962';
    smus['7.1.3'] = 'CSCvz75757';
}

var vuln_ranges = [
  {'min_ver': '7.1', 'fix_ver': '7.2'},
  {'min_ver': '7.3', 'fix_ver': '7.3.2'}
];

var reporting = make_array(
  'fix'           , '7.3.2',
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvy48962',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info      :product_info,
  reporting         :reporting,
  smus              :smus,
  vuln_ranges       :vuln_ranges
);
