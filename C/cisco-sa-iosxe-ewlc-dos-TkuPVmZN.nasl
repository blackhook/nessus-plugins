#TRUSTED a6ac57e1a543922f9202bd148b7c666b06320df67298842e7f4253a0fbe7fe67fb2f2cb538479bbe2dfe11593ea27bd45de62119cad2e97b16bdfb3ca349cc2c481bb0cf0b64607b81dbca564f9928bcb5c231c8e4e7928d5b447a2db89b8a57b9271a9bbcebe8a10f573c9f0bf076dfe2dc2a1a7b26c3f1af49f0ac6d44971757d92be8eacda78a8745a021e05d383836c5e956a2aae916e692e55d6da220a3e7f96537f3f8919a9496e2372b9e5915636683ad69c1ea2a39e43719a9f21a2edd43576d88777d18e817c5f2ff7bf5ca6ae760036ea75010421d67044e31af7b2db49f6c6c2ab154b1cb37db21c5decb81df8ff9267a0e9cd01ad2f11c83ce33cc36873615acccf68314698e3a432d50d38c034d74728b9acfe698ad871ed58c6ec879222eb63ba7d0f585f081710e061c8047b380243ee8d6498cc6f69a07d16a66ae90e94eccf0aa6f099b1bd855aa4b0ff3eaa79108a7e040fd87cc15df3aef49cc824175857c6298a5ff9ff0c5602a9ad342bf056a4bc8920a26f127f87038ed162328d6312df4fa79ef8cf8526df99a044be0f8f508bf973fa208ab6139d9df1555e8c340cf6a22865153405f44e8cf79eaaa158e58c575063142ce4a1750c9ee09295c50675757df99664cc074b2eb0c342e40cb2b3d3d6e4eb460c5cbb2eb3e4579bf879eccb250d98a35dd48af71a682f478af1035b9164cdd99abd9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138094);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3203");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq92421");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-ewlc-dos-TkuPVmZN");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Catalyst 9800 Series Wireless Controllers DoS (cisco-sa-iosxe-ewlc-dos-TkuPVmZN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-iosxe-ewlc-dos-TkuPVmZN)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a DoS vulnerability. Please see the
included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ewlc-dos-TkuPVmZN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27cffb9e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq92421");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq92421");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3203");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/device_model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

if (device_model !~ 'cat' || (model !~ '98[0-9][0-9]([^0-9]|$)'))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
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
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2a',
  '16.12.4',
  '16.12.8'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['trustpoint_lsc'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq92421',
  'cmds'     , make_list('show wireless management trustpoint')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
