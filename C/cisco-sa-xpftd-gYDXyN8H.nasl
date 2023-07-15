#TRUSTED 71817997620fa79c6899d92d0642092b99f705c71ef5474ee1d2696fca02df7229273d657174a4386bc4ca3afd899f5610b68e249462215073da815bae8a90fc6480466447d3aa77f5c598c801e8d8d58d5010548494d726c97a224293794288c4bfea9bde1cb5a384d4e32e8bb7554b0eee48de230609e8a0f364ff34ffc84bcbb6dce20760c6df05744e5067601a22373af622b7662fedb1578ab5cbf3a16c788f2bb2973a548fec237989f103c19a6790c4d7bf96ededa1f03ed5e014bf436e2299678fe71001abad05f20de410e193e20041b325af933f8fd7aa8ac855b39416351e151e098f8c060446a344cc484f1ed749e4287e3b14b74c2ec91c1fc63db452731dac28cc83ae3c340004d6ceeb58058aa49236688c27a07abef522d00ad57f90c6ef61612f1100e9fc70bab1fc0559dd104a51a7dc69b96b06cd65857517171484e4735b023c9add896d58a57c5f3f360033083b13bed887ec3707c2122a44a496ff01799795e669159f29d6907e460c325e2ab8caddfd2fd770d3bbdbabdfba51b7408e102fba005879c57b7da5f9f5078c2946d54aabdb5a8eb4d656cf1d7a416d1ee8455e715494f35b421e2c1d77dd776e7f7cbd4c92b6f76528e4fd25f443429985eb12bae0b76c2e2c490fc14da3e0c1dfd1d6a1ffcde98425d0d146b30a682f0f2d25ae2bc0dc3804e49ce7e0eddf76452e5091107cbe4c5f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138361);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/13");

  script_cve_id("CVE-2020-3310");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg48900");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xpftd-gYDXyN8H");

  script_name(english:"Cisco Firepower Device Manager On-Box Software XML Parsing (cisco-sa-xpftd-gYDXyN8H)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense Software is affected by a vulnerability in the
XML parser code of Cisco Firepower Device Manager On-Box software. An authenticated, remote attacker can exploit this
in multiple ways using a malicious file in order to crash the XML parser process to cause system instability, memory
exhaustion, or a reload of the affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xpftd-gYDXyN8H
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb987da1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg48900");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvg48900");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3310");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_device_manager_on-box");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_device_manager_webui_detect.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "installed_sw/Cisco Firepower Device Manager Web Interface");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('http.inc');

get_kb_item_or_exit("Host/local_checks_enabled");
port = get_http_port(default:443, embedded:TRUE);
product_info = cisco::get_product_info(name:'Cisco Firepower Device Manager Web Interface', port:port);

# Strip part after -, not needed here
if ('-' >< product_info.version)
{
  product_info.version = split(product_info.version, sep:'-', keep:FALSE);
  product_info.version = product_info.version[0];
}

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '6.2.3'},
];


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg48900',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
