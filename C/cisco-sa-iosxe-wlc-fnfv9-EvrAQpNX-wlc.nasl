#TRUSTED 03137c0dea2da0931d227d722a7c76fb1ed3003781ae5b66f13f820281fa17a2572e28d092ea4655536877e701817603dced53884ec810ed98037418a28c5d9aafdd8e8c062625d541b630cb86151f6422e5fc7d3ba76dc122ebda6e0a7e0b488d3c00b66b00684b82be09e4147c903c6637eb5dbdfd69ed8acb6c3ad4c4a5cee737ca41df98171dff8abec326c50ef30653a3649c5b12c3b13a1fb34ef6bd46321e0757f3229a02ee1d634313b65c1d05146333f2215232dbe11e689d5f4b8cd459cc917ce4bbde1e10d6de979412d0215857b89f2838dee8809f9f1b9b1ca66107cadbff8e8fd7990baa75acd80ad6b69329fbb883696ff7aecd2cefd0c619cc0abf2226dff8b1341f6de23a1dce4d07023d562951b0ef3635b45f8e09309a561389fbaac51125b24207aff003da29f3329ae0b6f3750619835be3c9b7914c8b690371055ce67a17f01ae0e74e5d85bc7577e7542cad3bff727ad9e3b87d4ed7799c04cb99d37b81bee0fb51e3b996f98e9441d1372fbec30109078b179bf7fe633ffd55995a8ba33a37c54c1391da07529e51f4c926a21daa9d7c45b439245e519de76e6843191046671e389439cae63d6857ae8ca2a59e9ed21d529b8381c1c365b24fb8a964c815dbb272cf9a4cb5c232a2c68ac8a0f4888313ffef5740867dd252d79bd401b0376d0f74c47c018b94446ae2c385420d6fad0f4211222c
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141369);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3492");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr53845");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco AireOS Software for Cisco Wireless LAN Controllers (WLC) DoS (cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Wireless LAN Controller (WLC) device is affected by a DoS
vulnerability in the Flexible NetFlow Version 9 packet processor due to insufficient validation of certain parameters
in a Flexible NetFlow Version 9 record. An unauthenticated, remote attacker could cause a DoS condition on an affected
device. Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f624c003");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr53845");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr53845");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3492");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '8.5.160.0' },
  { 'min_ver' : '8.6', 'fix_ver' : '8.8.130.0' },
  { 'min_ver' : '8.9', 'fix_ver' : '8.10.112.0' }
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr53845',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
