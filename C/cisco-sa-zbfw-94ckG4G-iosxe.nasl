#TRUSTED 194e1befa6789e9db0f09d77c0012a90aeace2832c5192b83c8cea623e18d48dad9a0a5ed9c8f403e547ebd82eb9edf4d6a5e0d3395c8192cdc6772f8f90ce13e5f3724630e134d6be86abe049a7ad48ae477455295ee9df16012b3873dd6602b63dbeb162a7f74adb68d1b51e1bf87839e6bfb661f0292eda3a9a4d340bacce7fa4d3d70cb92b9e79c645d01b0b05c2fc499777f2f4918d340acf39f19a514ca1dc114a053d6c13503488bfff9c918407bb0525e60c4d3a50af322fa2c5a680ef57f4d7934e36bb4b1cd8ea99004aa79f3a51e6d29f4c2ab361d1256b70cad2c35b79430df748fc3c47397b71f127603582862b967f9834bfc755930b12664aca53f9fd655ac854e6c1143e8aee3d68a63254ba4a116965520694ea7f5c9c5a1e5c6541c0de4b4ea11647ce8e62d777a90486adc97f3ea9a37a416c5171c9d7c5b41f686b7c1ec3f19f177b45a866245ced52731ce801a89021eaf51cc28b4715871a83241740d0963e077b208432bde91c49060393d71c6ba462d68cd58037b045cceb7c2e0b9dfe67c0eb75f1a44d7ed4d5809628c6d8a1ad29e5ccca376a526ed136a3ee2e1a6b660a6bd397725d1abb9b754371fcebad2fea5ecd56eb9f64f8c6ef02b0ec7f653361bea03428ba7f476aa9e621ecdfa071d1954123c99d270f4fa1e3cbcffbc82ee9998a4fdc61455f3f35f3aafaa330fdb8710bc0c32f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141460);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3421", "CVE-2020-3480");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs71952");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt52986");
  script_xref(name:"CISCO-SA", value:"cisco-sa-zbfw-94ckG4G");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Zone Based Firewall DoS (cisco-sa-zbfw-94ckG4G)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by multiple denial of service vulnerabilities in the
zone-based firewall feature due to incomplete handling of Layer 4 packets through the device. An unauthenticated, remote
attacker can exploit these, by sending a certain sequence of traffic patterns through the device, to cause the device to
reload or stop forwarding traffic through the firewall, causing a denial of service.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-zbfw-94ckG4G
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1a34db0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvs71952 and CSCvt52986.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3480");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(754);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1t',
  '17.2.1v'
);

workarounds = make_list(CISCO_WORKAROUNDS['log_dropped-packets'], CISCO_WORKAROUNDS['one-minute_high']);
reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs71952, CSCvt52986',
  'cmds'     , make_list('show running-config | section parameter-map')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
