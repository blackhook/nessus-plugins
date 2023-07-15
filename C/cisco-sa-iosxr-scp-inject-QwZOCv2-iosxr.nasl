#TRUSTED 3d14d6efb49f6046856df1a437cf7c82dc552d2e0bc93d1af736b222bab0f3612a994eae60e4f95f36a40c166086ff5d4aa984038940f08855248e780e324a6015e4dab28068efc46c6fd4ab86d1b7f20a35f9915db7082565e72230005b7c06a71b05190c04eb77f8a37b09c393ca1d9c225c32a8b73d1c24ffc303dcfa86828ba755a46d8c3a5b0521d67fa5d77549d7845296c5f3493ecd5500601072be103dee189f000d78635a42707b5de3aa7b5cb9088400f2ed34573573cde97319cc93d638fe964fccd93b60f451d4862b074d0020b412ece1740128907b61413a0c1fdf99b6ebe2c131cd5e0d14f5419cb697b966f67be6ba6305ac5323ba68c073aec0a07ad552a06e7625b84e819dfde60a67a2cbcf801276f09307272fd184649f2d2ce8e466d1fc9d3bf1d403be3c92a8efbecd3f1fa5c56385b4b873d4d389a0f3c8cc30895ed634f507c0eac1ccdfad83ad36cd0ee76d79fddac06c96e2d2986703d02181eee7e0ff0587de776f3de3c28b1073b65beefd2801108ec0202a3600771d0fea5d37c6634b26c164fa6fc4f78b0f10aace089f905031b7fbb6c92a3b325f18a6e5c0ad24758e083a553aeb3d5483184f5804d635db7e5bfae87e86448d65ccb620fe097ec52d4ab0cdae3d19f71df307948e98871f3c326370dc245b713196488d96b86487ed41da4703297b9af84cb279ca7862e15549504cf1
#TRUST-RSA-SHA256 9f71ccd8a8ba2f97eff33f33b1dfe31deb7c580ad3986768e9977d3bf177dc66122fd49d4dc2a1511be350bc46970715e02a253bb3967f170a6794ab5d991f0da16826f1d1cc3100039497bafef324357eed75f2096ae4e94cd676aabe64a970305879620705241f512035620a30e8ad35faa364154b10d02f9f14395915a99e3b23feec793a9731ae2dbec7b3b2927c083b2a2f38212ae47b37da867bbe90e658f76e832151e5ea9e04f56df45bfb425e798280e3d64ea266ce51167b2c0d6eab85a1d3b9ec04caaea0b6dfb69bd2d408d4651944acb9857ee56c39fd342527cc80e5e8a105d34aa45d63279ab1297a41d30d90a3db7e33310684f89b6bc0dc3d7498e56aa0aa95fc0a0e6184866054996cfd62a9a808011e2c706b8e33ce71656f84a5aadc9549df7d9649f53a6ec70e5ec0946a5f5900fa17702c89d3581513d22db4cb27162a6a7752bb97eb5acee29843233bf4fd956d3b9b9c2e4b6fc2032b3dcde07e4a92d5b74df4c140041096205a8aaa171f21f1955b535dbec8c59df5df87fbc7ad5fdec1a9c8cf2b4a67f1c0c6f564bd105744e284ce638a854656f8ef710015c14324d8da8465ab316c7275b51517f20c90607a7720be724d4bee038303a22b95b6ee2c83fbf3fd67adf67fa3a68d41eebc2980e8cd8a05a81b1a348e5b6381381268bf944ddb02fe8b14c533643c632f31347fb5bedc0432a5
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153208);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/30");

  script_cve_id("CVE-2021-34718");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx48017");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-scp-inject-QwZOCv2");
  script_xref(name:"IAVA", value:"2021-A-0407-S");

  script_name(english:"Cisco IOS XR Software Arbitrary File Read and Write (cisco-sa-iosxr-scp-inject-QwZOCv2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by an arbitrary file read and write vulnerability 
in its SSH server process due to insufficient input validation of user supplied input. An authenticated, remote 
attacker can exploit this, by specifying specific SCP parameters when authenticating to a device, to read or write arbitrary files.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-scp-inject-QwZOCv2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c358fbe");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx48017");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx48017");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34718");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');
var model = toupper(product_info.model);
var smus = {};

if ('ASR9K' >< model)
{
  smus['6.2.3'] = 'CSCvx48017';
  smus['6.5.3'] = 'CSCvx48017';
  smus['6.7.3'] = ['CSCvx48017', 'asr9k-px-6.7.3.sp2'];
}

if ('IOSXRWBD' >< model)
{
  smus['6.6.3'] = 'CSCvx48017';
  smus['6.6.12'] = 'CSCvx48017';
  smus['7.2.1'] = 'CSCvx48017';
  smus['7.2.2'] = 'CSCvx48017';
}

if ('NCS5500' >< model)
{
  smus['6.6.3'] = 'CSCvx48017';
  smus['6.6.25'] = 'CSCvx48017';
  smus['7.1.2'] = 'CSCvx48017';
}

if ('CRS-PX' >< model)
  smus['6.7.4'] = 'CSCvx48017';

if ('XRV9K' >< model)
  smus['7.1.2'] = 'CSCvx48017';

if ('NCS560' >< model)
  smus['7.1.2'] = 'CSCvx48017';

var vuln_ranges = [
 {'min_ver': '0.0', 'fix_ver': '7.3.2'},
 {'min_ver': '7.4', 'fix_ver': '7.4.1'}
];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvx48017',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  smus:smus,
  vuln_ranges:vuln_ranges
);
