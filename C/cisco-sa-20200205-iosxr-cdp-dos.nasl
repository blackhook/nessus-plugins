#TRUSTED 57b813b68df1a8f80dab37d0a9b89a56b1c5259d493bc91acdec00d6ad5eac653956853ead9fa6ce5d958df5fdf2a9f5573dd29103634a699c207b5a2faa17184bb80df05021eb1338bc378c3a12fe4064cf8b7b696b8712f09a414db1126b01764df5a583ffb5588e7ff1264feabe40bb90ecd9e7289171c9c9396187c555af58ff5a8710b52cced2cffb5cc38a087fa97b38f599dc4ec4884c9443af22cc69aa6d5405d95afbee234465c6143d902ab9b27a534b6c21b8561705dca366a8c9966a208c075a9f25428431e6f0d3152be212268df0d69014b1176d0393bf79b1588e690a50edb111662b364aa70165ec4ff246c8218c4eae88194d85a75e65919497e3dc7050684b47d5cddad56199f3b66c7b355b0804655b12eb5c57ee92edbf2f0bab497f738125a515299580816fc7eee48680783d7e16dd234b9f2372ed66158637e50210626d497098bc107f2fba44027a76b3158aaa3b2176c0af95b5a29242c78edbf511bfad989437dfcb96bd028cb653434af3e51c02e495b9502de9436b2c46fb78e8318b6bbad2386252e2493361e73c81924ee1ab0066c104ad46262fa2de6287488fa6f62ede5a5e054adc0279411aab69621e73118ad61ad1be0e5da98ed7272e8d06ae3bed19228e02184e1cdd48015293f67b5b951ab32a66e02b60dac921c61de1f283ddf4248c7ebb64ca300ebf508cc28a465821693c
#TRUST-RSA-SHA256 acfe398f3c78e9ea82100dce96c15c9e0d8a2b8e74ebc2ad5828d66c0e97c33306351885a751e1f982f2fd6144c0484fafad2a784858794a62d9daeceed598f4cb1a3bfec6aafb3e331061e077a3e66c28eca9440557fc913d890e84036e35372d4fe14384fb72f41e33e9fbc308fb32a6ab15ad84325a9262f0fadf42290abf1eae1c22b12a70ba681f296b73ef221923ece54fc69fe8b6aa4a3ca7f459cf5b507221099042e646f13a9eabff69278005c401553eeddb80dff9e83fa5555c2d461b7d0b9da9672be2e947440bb5dba930049cd43313af9c738a2dd7a1f16d95991bb2f66485f4fe2af6a1136470880acaad0efefc5246f5b31cdcba237e3dc30fc6d88386c2e963e2176d7bb07b33d27c6480bcaae44765d3d3ca69025a6e6015ac0a7994bcec88b15554b1a025a6c867360f84623fa6489af7c30765111b37133b266831c0d936624455d44eb011866cbc4ad7a209ebb08a1053e2f4a71dd633d7cc8fed50aadd30d91de3218c2fe9367941ab937a716eb0ea0248bd5867023fddf7ab6b92466c8542e66e99dde73e58d8f36b1569cc152cbc85d04dd30ddb727878ebc1a82d207828dda8f57dc62a7925df9312bb577591e302eb990bcb486bd6f6fda7c61e34e9aa777e502b8c16139dd3717c79951e82edec24daf16c9cc1d3cc1b7145921a1e7607ea38b0ad81c1b1d9bc543955d08c59c12da8f606d5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133721);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-3120");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr15024");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200205-fxnxos-iosxr-cdp-dos");
  script_xref(name:"IAVA", value:"2020-A-0059");
  script_xref(name:"CEA-ID", value:"CEA-2020-0016");

  script_name(english:"Cisco IOS XR Software Cisco Discovery Protocol Denial of Service Vulnerability (cisco-sa-20200205-fxnxos-iosxr-cdp-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XR Software is affected by a denial of service vulnerability
within the Cisco Discovery Protocol due to missing a check when processing protocol messages. An unauthenticated,
adjacent attacker can exploit this to cause the device to reboot.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200205-fxnxos-iosxr-cdp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3303b2ba");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr15024");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr15024.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3120");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ('ASR9' >< model && 'X64' >!< model)
{
  smus['6.4.2'] = 'CSCvr78185';
  smus['6.5.3'] = 'CSCvr78185';
}
else if ('ASR9' >< model)
{
  smus['6.5.3'] = 'CSCvr78185';
}
else if ('NCS5500' >< model)
{
  smus['6.5.3'] = 'CSCvr78185';
}
else if ('NCS540' >< model && 'L' >!< model)
{
  smus['6.5.3'] = 'CSCvr78185';
}
else if ('NCS6' >< model)
{
  smus['5.2.5'] = 'CSCvr78185';
}
else if ('XRV9' >< model || 'XRV 9' >< model)
{
  smus['6.6.2'] = 'CSCvr78185';
}
else if ('NCS560' >< model)
{
  smus['6.6.25'] = 'CSCvr78185';
}
else if ('CRS-PX' >< model)
{
  smus['6.4.2'] = 'CSCvr78185';
}
else if ('NCS5k' >< model)
{
  smus['6.5.3'] = 'CSCvr78185';
}
else if ('White box' >< model)
{
  smus['6.6.12'] = 'CSCvr78185';
}
else if ('NCS540L' >< model)
{
  smus['7.0.1'] = 'CSCvr78185';
}

vuln_ranges = [
  {'min_ver' : '0', 'fix_ver' : '6.6.3'},
  {'min_ver' : '6.6.12', 'fix_ver' : '6.6.13'},
  {'min_ver' : '6.6.25', 'fix_ver' : '6.6.26'},
  {'min_ver' : '7.0.0', 'fix_ver' : '7.0.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['cdp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr15024'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus,
  router_only:TRUE
);
