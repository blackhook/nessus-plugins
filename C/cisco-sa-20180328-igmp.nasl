#TRUSTED 888aee691621a4705c2d6a16ab9bf0b944ecd24f6b4d76b89a38354e714bf9cd2b7337bb441b73a628269f781b7ddc33a6494aa1d64f2725cc5ebebf164e98c8588f274b534bf8cbeae7508ee65d8280f2bb67785a308b7e6a89bd42aad1d994f921d26e3af98f2c2f31303c2496b23e0d97569b08d7c9e63f9a1c2fdd8cd25b1fa11630d09f764c3e36fbde22c5e51fe9d2970b3bee5d88dc369a82b5b99290d1b4dbde4ef49116a2393e1fc3910404365e595978624f213ceab0fa783751be3c7b6e609e64f2e3b74c048da04a61ff5eb4fe3a88ec03d7eac7713504393813af3191f3a344ae36f16550e236411074368afb4120e4df7cd006a7e1f99e8bb27fc6533be42f05394b6993be49ba0449d44f05d229f2fd8c74434c3d1ed4d26fe4a43f46d1f36dde9e022fa18ed90e4468a7c108b785e11df38404c8249438549f73165bec8c83982dba4a508ac62d5ad5f81625cb9580c1e1ad0d6305eac2dc568bf2796507d4f9fe62d1606e229553a75c3fa5e47bd91748410e6cf348a23c44bcb748738d34afa0eab07900b116832155bc5ef538ec9151ad37810a80b88dab010475942e2d92d430a6bdd0da19df0280c7d622b7f628ec7d197c460edf0141682c24ca26e2a16136b4e1f20a3207230e050df23cf7bb1230c421ba224b2e0870f2cae39974e007c310c50838d5590d31de4c0213df9e05f79d6f39ecefa9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131399);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2018-0165");
  script_bugtraq_id(103568);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw09295");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94496");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-igmp");

  script_name(english:"Cisco IOS XE Software Internet Group Management Protocol Memory Leak (cisco-sa-20180328-igmp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Internet Group Management Protocol (IGMP) packet-processing functionality. An unauthenticated, adjacent attacker can
exploit this, by sending a large number of IGMP Membership Query packets containing certain values, to exhaust buffers
on an affected device and cause it to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-igmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be52db3c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw09295");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve94496");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuw09295 and CSCve94496.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0165");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/29");

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
include('lists.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Only Cisco Catalyst 4500 Switches with Supervisor Engine 8-E are vulnerable with version 3.x.x.E
version_list_4500 = make_list(
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E'
);

version_list_all = make_list(
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.4.1',
  '16.4.2',
  '3.18.3bSP'
);

model = product_info['model'];
show_ver = get_kb_item_or_exit("Host/Cisco/show_ver");
device_model = get_kb_item_or_exit("Host/Cisco/device_model");

if (model =~ "45[0-9]{2}E" && device_model =~ "cat" && "WS-X45-SUP8-E" >< show_ver)
{
  cbi = 'CSCuw09295';
  version_list = collib::union(version_list_4500, version_list_all);
}
else
{
  cbi = 'CSCve94496';
  version_list = version_list_all;
}

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ip_multicast_routing'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi,
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
