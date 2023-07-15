#TRUSTED a6042630e3e8b90031a52a22b136daa87acb3bacae7ba037dd1758253abdb945c31886105c1f04f4479ecf55aae7dc9aecdf3e2e59445326a758155d6ce90fc77ed93534f0c0a3de212cb10373ccfd19747b6f0e482c38234767b1dcca1de289ad9e53d658432dff6017ac448eb028d346d863c8645369db7113922650ad4a14e1e66cbd75e4e6219b5dd732c1829474168fd3dfae6257a160c713bd3283950a8a34cd4a885ad6a2398169530498d881c265865a739c8a24cbac114c493f55717cec71b576e609c876c38269b4c09a8608e8ceacc290bac2d657ac9205afda038488357a0523ea311fa92e4014de12dc1dd4131b048b60321c24faf6d0addaa40536731ed8e1f275610686274320d694fca9381251e3c4a2c366676fa298ec0a43b53cec862e37a9cd6452bfa4074b7d854d2611c2a94fbf2de0a01d6089fabf0976a32bf7948f5a6489ec403006ccbfc6fcdc188872bc8322eeef6c173aec2569e73973c459344ad47d7156703cf1eeadd5c29a15777e2a2d1d9c256bcd1f9d659e554e0f61cd2ecd6decf2e7d084fdf36da8762e94f34d2a6c1df4823492c58a00a70497af67ea34b992e270fb2055e2cef37d2be0f86d46bd3bbefdda8f8a1209b3534950e5f7116675042a8fd387c9733d77779a30ec5bfa9b14303f166d91c0eedb46fd6346e461b68bb801232a067114151eee90261ad7062f5314d1ba
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160029);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/27");

  script_cve_id("CVE-2022-20692");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy95621");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ncossh-dos-ZAkfOdq8");
  script_xref(name:"IAVA", value:"2022-A-0159");

  script_name(english:"Cisco IOS XE Software NETCONF Over SSH DoS (cisco-sa-ncossh-dos-ZAkfOdq8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability in the NETCONF over SSH
feature of Cisco IOS XE Software could allow a low-privileged, authenticated, remote attacker to cause a denial of
service condition (DoS) on an affected device. This vulnerability is due to insufficient resource management. An
attacker could exploit this vulnerability by initiating a large number of NETCONF over SSH connections. A successful
exploit could allow the attacker to exhaust resources, causing the device to reload and resulting in a DoS condition on
an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ncossh-dos-ZAkfOdq8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?049a1c9f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74561");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy95621");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy95621");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20692");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.3.1',
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
  '16.3.10',
  '16.3.11',
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
  '16.6.9',
  '16.6.10',
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
  '16.9.6',
  '16.9.7',
  '16.9.8',
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
  '16.12.1z1',
  '16.12.1z2',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['generic_workaround']
);

var workaround_params = [
  WORKAROUND_CONFIG['netconf']
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvy95621',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
