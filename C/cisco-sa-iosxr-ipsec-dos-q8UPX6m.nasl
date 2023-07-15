#TRUSTED 2d307f63cec6f6d981e8f7582c76e42a5b034215c5660d6af613e08aff755c23a04cea1ae7fce139dd2e75d53422fdfb9b30328079ba51ee4b8def8abc08f3e90e6df872101e4eecbec0c8145fa9d541941f6022a48e03d4310071521dac3a0373ec9b7c52d414438161f94189cfa073ebdbe281e8a822bfa95e7ecf0f976a63ad098079f288d957d5cec1f6dead242b67e2206472e16f6c3bbf657162a7bc65538eca9e67580f00eb391716a8efd1dc1a8be65e3ffbaac0d17b3e67686179d88907bd1ba59d6b8195116b2ee75e4469ea91acb12f1f02bf5bb80a3ca6f1034f95986875feeb446615c3464bc3737dca6c444b553e63a8419d4be27fde2805c484aae77556b2855d39d270297423bfe69ebd15b7a4f834a3b9f514b94725b33fb01ce476da71b57271d42fe31999459d5089a14d755960ba25a6d32ae5d5244d93d7cd6567e403bd8ba2b8312c8206176cc5219b3525d6efde2bcbb535200dc360be9ad9793f61cc61eb1ac181b068276eced6667d96688a31d5e88e78f398bcbf4837b5cca1531d047f5175eec4c07460de5cdf04077e02f748afefb3544d803f356fa2980b91559e39b7fc7c7e26ee014a2edbb65b43f094d2ed73eb70b0c14c5b8b93a141f7732c96e034c98656564aadc09afe652c27b2c3a0db996587ea223f03e2c54b8f7cd723a5bd69197f1244391d1a49c0e7c3946324d280397421
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134451);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2020-3190");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr75998");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-ipsec-dos-q8UPX6m");
  script_xref(name:"IAVA", value:"2020-A-0041-S");

  script_name(english:"Cisco IOS XR Software IPsec Packet Processor DoS (cisco-sa-iosxr-ipsec-dos-q8UPX6m)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a denial of service (DoS) vulnerability
in the IPsec packet processor due to improper handling of packets. An unauthenticated, remote attacker can exploit
this, by sending malicious ICMP error messages to an affected device that get punted to the IPsec packet processor,
in order to deplete IPsec memory and cause all future IPsec packets to be dropped.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-ipsec-dos-q8UPX6m
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29db06d4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr75998");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr75998");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3190");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
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

model = tolower(product_info['model']);

if ('asr9' >< model)
{
  smus['6.4.2'] = 'CSCvr75998';
  smus['6.5.3'] = 'CSCvr75998';
}

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '6.4.3'},
  {'min_ver' : '6.5', 'fix_ver' : '6.6.3'},
  {'min_ver' : '6.7', 'fix_ver' : '7.0.2'},
  {'min_ver' : '7.1', 'fix_ver' : '7.1.1'}
];

workarounds = make_list(CISCO_WORKAROUNDS['show_processes']);
workaround_params = {'pat' : 'ipsec_(m|p)p'};


reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr75998',
  'cmds'     , make_list('show processes')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
