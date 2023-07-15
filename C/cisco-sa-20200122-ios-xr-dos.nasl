#TRUSTED 4aa4562079badba4f87d0a693b5a91a88b00b9c6358b1bffd15642f2e911b1fd160d7ee6af77bd21e3856618c502cdc6f03d1ef8eef8d55e8996fc99b8a4a590fc5a213c1c1b14da9fa35f8d2497181693341ed0a63805051497da80242d8e24696cedd742aaef39206905d5caa8cf31602c213f3dc95b96d840d86e057298a96ef35fb19236f8e7289aa66bd8e035162aade038f0b046a3c24d2cb6e39ca333b96f95add9dc285fcf06b7d5be8bfc7b7f8853220cc4b3063ef427afce1a1fefba39c12bd5477f8f07d2cca5e44690363ccd84793fd72a232719c16b111cb61fb0bd6edd5b28b73a32e0d757267fdca473b12106226159ce8f064c58361165002c4f2bd88863007d77dcd1e5c516ce80d79f3334a95e19372c2e6d55ead7addcf8960aaa79a7621a1d820a9fd3f21a94fbdfe83a1e18005d6aef238e5f658ce9fb426e04364b5f165b44dfa328337d986aa5ae9a7eece4893998218afcf0c6bb5a69eb919b540647bb0c57602b0a26d1854aefcc58ab6313e630a9cd14a4640dd586be51311bede0cb7b823284bfd758f3eac500ee79d453a847dfd265d046d7de68a46a6ef64463e32623e3723bc0fda1b030dcf1c57c9f789cf8fdeab9f7b87525b63b37b102bc11852a276d3e0325239f6d103b91418f5f4f4d05290ee40e4e66bef191e282e43bcafe5903a0380a57971fd6e2198ab4beabcbee3fa5de19
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134447);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2019-16027");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr62342");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200122-ios-xr-dos");
  script_xref(name:"IAVA", value:"2020-A-0041-S");

  script_name(english:"Cisco IOS XR Software Intermediate System-to-Intermediate System DoS (cisco-sa-20200122-ios-xr-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XR Software is affected by a denial of service (DoS)
vulnerability in the implementation of the Intermediate System-to-Intermediate System (IS-IS) routing protocol
functionality due to improper handling of a Simple Network Management Protocol (SNMP) request for specific Object
Identifiers (OIDs) by the IS-IS process. An Authenticated, remote attacker can exploit this, by sending a crafted SNMP
request, in order to cause a DoS condition in the IS-IS process.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200122-ios-xr-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bf94d9f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr62342");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr62342.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16027");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

bid = 'CSCvr62342';

if ('XR12' >< model)
{
  smus['4.3.2'] = bid;
}
else if ('NCS6' >< model )
{
  smus['5.2.5'] = bid;
  smus['6.2.2'] = bid;
  smus['6.2.25'] = bid;
  smus['6.2.3'] = bid;
  smus['6.3.3'] = bid;
  smus['6.4.2'] = bid;
}
else if ('ASR9' >< model && 'X64' >!< model)
{
  smus['6.1.2'] = bid;
  smus['6.1.3'] = bid;
  smus['6.1.4'] = bid;
  smus['6.2.2'] = bid;
  smus['6.2.3'] = bid;
  smus['6.3.2'] = bid;
  smus['6.3.3'] = bid;
  smus['6.4.2'] = bid;
  smus['6.5.2'] = bid;
  smus['6.5.3'] = bid;
  smus['6.6.2'] = bid;
}
else if ('ASR9' >< model)
{
  smus['6.2.3'] = bid;
  smus['6.3.2'] = bid;
  smus['6.3.3'] = bid;
  smus['6.4.2'] = bid;
  smus['6.5.2'] = bid;
  smus['6.5.3'] = bid;
  smus['6.6.2'] = bid;
}
else if ('NCS55' >< model)
{
  smus['6.1.3'] = bid;
  smus['6.1.4'] = bid;
  smus['6.2.3'] = bid;
  smus['6.3.15'] = bid;
  smus['6.3.3'] = bid;
  smus['6.5.2'] = bid;
  smus['6.5.3'] = bid;
  smus['6.6.1'] = bid;
  smus['6.6.25'] = bid;
}
else if ('NCS5' >< model)
{
  smus['6.1.3'] = bid;
  smus['6.1.4'] = bid;
  smus['6.2.25'] = bid;
  smus['6.2.3'] = bid;
  smus['6.3.3'] = bid;
  smus['6.4.2'] = bid;
  smus['6.5.2'] = bid;
  smus['6.5.3'] = bid;
}
else if ('CRS' >< model)
{
  smus['6.1.4'] = bid;
  smus['6.2.3'] = bid;
  smus['6.4.2'] = bid;
}
else if ('XRV9' >< model || 'XRV 9' >< model)
{
  smus['6.1.4'] = bid;
  smus['6.2.3'] = bid;
  smus['6.4.2'] = bid;
  smus['6.5.3'] = bid;
  smus['6.6.2'] = bid;
}
else if ('NCS6' >< model)
{
  smus['5.2.5'] = bid;
  smus['6.2.2'] = bid;
  smus['6.2.25'] = bid;
  smus['6.2.3'] = bid;
  smus['6.3.3'] = bid;
  smus['6.4.2'] = bid;
}

vuln_ranges = [
  {'min_ver' : '0', 'fix_ver' : '6.6.3'},
  {'min_ver' : '7.0', 'fix_ver' : '7.0.2'},
  {'min_ver' : '7.1', 'fix_ver' : '7.1.1'},
  {'min_ver' : '7.2', 'fix_ver' : '7.2.1'},
];

workarounds = make_list(CISCO_WORKAROUNDS['snmp'], CISCO_WORKAROUNDS['isis']);
workaround_params = {'not_v2' : 1};

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , bid
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus,
  require_all_workarounds:TRUE
);
