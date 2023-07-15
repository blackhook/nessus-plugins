#TRUSTED 5b0787e516f0965d4da7dc503a768e2b2b5ed2c19f47f68920f2d8e0b1e015168b7b750f865d7da8031c677d38c26d9fcfa68ee4b2ef2300917e9fd53ed9983a597c3a89551303746b702ada75dd3ae6ceee40e3acdfde79c8acffc9a3f60c06a836f7fbdead01777717292170a81d43199066fcb40b8c65d59a9e37ea7ab14a8f1866a150ce1b8e13a9ab37ac090e746c1467ccc960ee25bd7e691740db289920c78ed974e8c01496a3d9d41f6ed558ea75ccf17f02282ae0bb6ca3dbb5b3fe2ce88ce04083a2a87c2611c67b0608e67b6c89e6213e8fd053c906b5e998ae3968c541e455a313bf4a397717a505da81219be9094f650e588924b3974b1f047f939ae9ee946555502610539bce3d55b40a9bda5bb6ac8fd89d6b9580676617c64ace7774a7a7b446fae3cdd1095bebed9049e18b34eacef77d8c34a848443703f44c0df1e71a2bceb2a1b36060d4216a3cb445dac365aee5165bb3f1ca7744687568c73586f4680d57e3ce49d407921844ada71e7bda7d12d1c4a75be1a61b2837d97f58ca58fb16764fbf8c499993fe4ae561b1d2da50938d02eab1dee7371253f554bf3e68dd0de99f5b59ac457980116aaa164156a0799e3fd1494d0c698497f6e8b00ad896232ca36adf89f67a8cf5db3e2830b32da6e71de8cdd175a25a7be928adf9709f14a2d529eefb752240d1c2f5156fef70c026b1a2359c3adf7e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135407);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2019-16018");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr74902");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200122-ios-xr-routes");
  script_xref(name:"IAVA", value:"2020-A-0041-S");

  script_name(english:"Cisco IOS XR Software BGP EVPN Operational Routes DoS (cisco-sa-20200122-ios-xr-routes)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a denial of service (DoS) vulnerability in
its Border Gateway Protocol (BGP) Ethernet VPN (EVPN) component due to insufficient validation of BGP updates messages
which contain crafted EVPN attributes. An unauthenticated, remote attacker can exploit this issue, by sending specially
crafted BGP updates messages to an affected device, to cause a DoS condition on the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200122-ios-xr-routes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0d123ba");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr74902");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr74902");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/13");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

smus = make_array();

if ('NCS5500' >< model)
{
  smus['6.6.1'] = 'CSCvr91660';
  smus['6.6.25'] = 'CSCvr91676';
}
else if ('ASR9K' >< model || model =~ "ASR9[0-9]{3}")
{
  smus['6.6.1'] = 'CSCvr91660';
  smus['6.6.2'] = 'CSCvr91676';
  smus['7.0.1'] = 'CSCvr91676';
}
else if ('NCS540' >< model && 'L' >!< model)
{
  smus['6.6.1'] = 'CSCvr91660';
}
else if ('NCS6K' >< model || model =~ "NCS6[0-9]{3}")
{
  smus['6.6.1'] = 'CSCvr91660';
}
else if ('XRV9K' >< model || model =~ "XRV9[0-9]{3}" || "XRV 9" >< model)
{
  smus['6.6.2'] = 'CSCvr91676';
}
else if ('NCS560' >< model)
{
  smus['6.6.25'] = 'CSCvr91676';
}

vuln_ranges = [
  {'min_ver' : '0', 'fix_ver' : '6.6.3'},
  # 6.6.26 is not listed as a fixed version, but it's here so we flag 6.6.25 if SMU is not installed
  {'min_ver' : '6.6.25', 'fix_ver' : '6.6.26'},
  {'min_ver' : '7.0.0', 'fix_ver' : '7.0.2'},
  {'min_ver' : '7.1.0', 'fix_ver' : '7.1.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['BGP_EVPN'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr74902',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  smus:smus,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
