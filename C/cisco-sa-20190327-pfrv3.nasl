#TRUSTED 9062ce32bcbfcba65a3706f3405a567d241ec7d3e76993581b4466bc0a0164b8550bed6d86a91abb1ecd510b08e700fc2c25d219ff29011372a61c940be6e3c3c44d50a695c15996092837feb3230b7a0291ddbc39bc98bf540306959c2e8718893055ed48d83d118aabe771cd99e95204dc3378f300cbd9eacae5d097350f7ab477ce1126de17f691a6c6cf22f8289792c34c7a0cc681427500bf472c2d43d4fa49646f04ace5cbe8f0033c2c1458c8dc34d7342b1c726451bf78119f9b75ac0704ead58799143bd4354da85d58b68a9448ed6dde7a47a2a3fc2f34a6fbdb79504a4883be8f23a29ad32d0ac710d764f9b79ac337685af81e9929047a5d765921eecaabe7651f8c7a437b487f46cc8f9eb647b03faf06ba0c8146e255af88f0b258002c1c8b345cfc3a8cc978fd9b2c52689bf93c77aacae4b0f103ad201a5bb6080e77e43863ea612b9b9a2cfa5d629adaf41424284943ed5e38fe864ea31ca4a27d14ca354977bb05e64f0dd52a00d6180cc2049c2885bd7a85b58f095ddef181b30d822095272194d4c97f58546cc9473971126a54f29cb7b40f6090908638e8795519ecc9d62e77f8e07ae88fefb604ba38497e96b850a6d56918527ff4c1a8917b764eda1a0a698271091ee5c6e32297c2297c77e1762480dd69db3ac5c6aa9bd6cd4982994f6ae7c4ed4279235bf4d7b7c0d4fdf18d922bc950a777ba
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123795);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/27");

  script_cve_id("CVE-2019-1760");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj55896");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-pfrv3");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Performance Routing Version 3 Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in Performance Routing Version 3 (PfRv3)
    of Cisco IOS XE Software could allow an unauthenticated,
    remote attacker to cause the affected device to
    reload.The vulnerability is due to the processing of
    malformed smart probe packets. An attacker could exploit
    this vulnerability by sending specially crafted smart
    probe packets at the affected device. A successful
    exploit could allow the attacker to reload the device,
    resulting in a denial of service (DoS) attack on an
    affected system. (CVE-2019-1760)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-pfrv3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?250f85b5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj55896");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvj55896");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '16.8.1s',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['pfrv3'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj55896',
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
