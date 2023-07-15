#TRUSTED 78037d10d5deac56848ea432b1ba6872189b2955f372b6e73ee32d43efd31bf73d47666a1b5abe8cf88b50f45d31c191fa957f6f9196f8b8442cc4a511ce3acc9ee752fedb9381a6fb4eb187dfea0f7c701e841a630ff520f9b9c8c54d09de78d44f9496c42c7b55ded52c495fd74ff44f2e4f5748ae53bb562d827b18f6e7c20fffddc379bc38a4a92382b57043365476bdf388beb49d52d280f9080cafa549268e7720392bec0e24e58322bf2966b8012f70df9e3f53e967b39d528d897b707a298605240e5771095e9dd4e80bf713120d0cceadc2015b321140e2d950cb44858a6cb29ce18fded791ffd8c95614f8ef4e55b750fc795c13ebf7b4c253f325c4498496fd2bc2335494864161fb9797bb8531e21f8cdc9e557e74309283481be315356d229096b290e703d9fd302f24acd56703235e1adfedc349372b22c1092c5204e57c1efce307fba2a66eae8e7e2e1f1712e31673e8ecb18520e553d2d073bb8ed1f9967d5f2b1b8695ee7173a759a5e179f363c748262be2a894fd89f9c0a59868a3011a1a8d69f320946098745744523516bd78ef6daa5155aacb94b200ebc11f28d703fdac94c98d4ac4ae70c1cdd106ec7480e314368f58db7fd4114cb8ad5178a3751cecc10a77541f4b56adaae91d9af5c224269969a3b67c1c7d4cc119dcc567ac05adbc0aeedb9bb5655f2501ca839903c600033f12eb2a96ef
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148250);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2021-1288", "CVE-2021-1313");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy67256");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz39742");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-dos-WwDdghs2");

  script_name(english:"Cisco IOS XR Software Enf Broker DoS (cisco-sa-iosxr-dos-WwDdghs2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XR is affected by multiple denial of service vulnerabilities:

  - A denial of service vulnerability exists in Cisco IOS XR due to a logic error that occurs when an affected
    device processes Telnet protocol packets. An unauthenticated, remote attacker can exploit this, by sending
    specific streams of packets to an affected device, to cause the enf_broker process to crash, which could
    lead to system instability and the inability to process or forward traffic through the device.
    (CVE-2021-1288)

  - A denial of service vulnerability exists in Cisco IOS XR due to improper resource allocation when
    processing either ICMP or Telnet packets. An unauthenticated, remote attacker can exploit this, by sending
    specific streams of packets to an affected device, to cause the enf_broker process to leak system memory,
    which could cause the enf_broker process to crash, which could lead to system instability and the
    inability to process or forward traffic through the device. (CVE-2021-1313)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dos-WwDdghs2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62a59336");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy67256");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz39742");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCuy67256 and CSCuz39742.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1288");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

# Cannot cleanly check for mitigations
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = toupper(product_info['model']);
if (empty_or_null(model))
  model = toupper(get_kb_item('CISCO/model'));
if (isnull(model))
  model = '';

smu_bid = 'CSCuy67256';

if ('ASR9K-PX' >< model)
{
  smus['5.1.3'] = smu_bid;
  smus['5.3.2'] = smu_bid;
  smus['5.3.3'] = smu_bid;
}
if ('CRS-PX' >< model)
  smus['5.3.3'] = smu_bid;

vuln_ranges = [
  {'min_ver' : '5.0', 'fix_ver' : '5.2.6'},
  {'min_ver' : '5.3', 'fix_ver' : '5.3.4'},
  {'min_ver' : '6.0', 'fix_ver' : '6.0.2'}
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCuy67256, CSCuz39742',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
