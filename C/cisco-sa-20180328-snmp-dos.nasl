#TRUSTED a5756612fdb408e1aba64963a8a7c1c275509a64f630c3e1d3e4454b280b5d53f95b187ee30b615218aaf60db977efe14cc75a38c7f5345345b3dcc30dc0ae7ac39b269d620a9cd1d7f32e4cf148dbeb2553bd2802ee1556203701273b900554e7e29f6913f3400211a81136ebba782b879a6a06074512f316b32a8e26bbe9fdb2ec2675a1d2fe39a17f6df64bc53641a552f98972c68fa4776e4a1306e295cc4f6c24da2b2e350acac7272adaca144bc1564ef44896897ce178608fc5735da08b07181c185d6fdef05ef061818a1d65a76b96fdd8f925bb49ca89629fc434b5c996b3ec9507bb956d0b479ff8cbd67a07ca08b9e0f73189a4718e13fcbec4f889b74cf7abdfd30b4ba32e1ec4b289e63ea496ad68ce16dc9e6725ec63e917faa969f2b3101027b20240482bfff748574e8a1e0fe8d5ab17602abf4d2611635f7313ca77ba17f0727b8b038ce00fbc442a955205fd106514ca8ec76d75f06a0af049775819f81e628c3b9612492e6a7b1a82177fd0d6b27ccb2c12b074384d32408e454e20501565b26cd4274b83be33f38a247856b9f6080fd7eb218ec02b255820557b08f441090f55fe557faaa16c299d77ee44eb6db3897726d38c12b78bb7b23a21c475ba29f8f78c6836d8486fbd470b3dba092c6d80e282d2c7a69bddc71ae137572249d376fb991c1eca9d48b4c12d90dd212248a9d341f9c681a13b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132039);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2018-0160");
  script_bugtraq_id(103575);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve75818");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-snmp-dos");

  script_name(english:"Cisco IOS XE Software Simple Network Management Protocol Double-Free DoS (cisco-sa-20180328-snmp-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Simple Network Management Protocol (SNMP) subsystem  due to improper management of memory resources, referred to as
a double free. An authenticated, remote attacker can exploit this vulnerability by sending crafted SNMP packets to an
affected device in order to cause the affected device to reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-snmp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b77f9f4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve75818");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCve75818.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0160");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.4.1',
  '16.4.2',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '3.18.0aS',
  '3.18.1S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '16.6.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['snmp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCve75818',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
