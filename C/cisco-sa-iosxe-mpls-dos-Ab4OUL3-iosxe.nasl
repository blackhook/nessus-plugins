#TRUSTED 5e94500a97af136e4bd6575cdfa84f5b462359142fe1b801f9cfe63579e0979552fb4c6d79da349973966b514f21d310ba5e0599e80bfedfe596a700a13dc8b2762f9c837f78992cee7e403900e126f8a9f7a1d8eb9d746ef9f0c0936b031d75d942eccb6831274b1a8c799a61aa7d56c1f3cf2b5a4043d58acc277d345cc7133722028e1787ce998e9147d8253a8d59f95c5a429ffd4bc7a5b954a5928576fa180229302b55cb9ce13bdef0689f612b03924b3ae98ed160f4ba43a730a01146cdb90ca07d80e24c530b5ad3bd3fcfa7ee17349ef5758fa931abad7749753b4c9d9f8497e097ad9bfe83342bd9c6f742d9abc805d9c8f65cee1c503e5b834b82835b1ebd8a589f8b6328273bb14c62bef9d7352c4bf3d4e429f0d4f859edad18302f8bdfbdff1bb702115d4d9685acc059e18260fa6ca9bac65f4c25a4d75a988089bd6fe0cc9e119ff42a99537e4783479f5b2a71e0096b0fbc3259c2378925d577c11ca7f3aaca87e23991daeb8d7c81414e90820e5548063d16f9cd21e35212cc23543cb4c3f90541dd7978b588bdc1201b160bee6bec6659d255493d06bc0de1fa632d0e8e736ad999408850b4ba701688efe2838eeedb90a5710cdd24380e04b787ca894c65e2d549814c26a5435a033bf8773bc5553091a98f7c331f6036b18adbd63b18e0262c6703ee5e09e4cb9462971f6c49f62e255e9e8ab836c5
#TRUST-RSA-SHA256 abe5176892b20fb7f052f197d5f14b707529a0d8c9c07812edfb2bba71c0ef47ea6d62a7df2da137394f85c1613fa5ed2cbc2b46506280a4f7fc53dff3cdb05fa297113d3d4b0e028176b8fe5b889fa2f51da08ccf9f90c38a040ddd9b35d81ee567435359a226d0c32936780bb0bf544711d7495a36394405a70813d9967827b656e36a18025f3928cf5268928b6928a7b295b4afd34d2b38f6d6f1d01f32643f2574ca420db89ac6e0efaf2f0cc93cb8ce497906bc3802dd0d45dc76479888022b3edec797f215d9030b4e652e4ac0fb9ffca3ffa7c90a90cecf5061f5ed024335c45ea361c436411a6b4159520928d3641d860e02120c9c4817fa2f3b68980b91050608b3d66e1e3d8e8de88c6405eaea0084cd9c86e2d9a7993f7bc9f674ca72738a5774918462f78229661e95bc619b0db80b00bf302f1bdb57eda9364e960bc61b734e5f5522f5c343b86ec4cc1f44be3508f67ea46c5f11dcd44f3b66bb5a67517e31847801bd37ecbcb9cd11cb70b09a414af9f9d909bd7917e9fff09da71ad991095f2f8cb78928060d7df2a4cdffab1ec9f1f4b4cbdc615c0f37c1f3d57c73efcfcbd0b6c9b65141abc783e961d4dff7ca55c94a94b3847fa0ba0ed6f764c89b7877fa5ee29a0b92895f9120ac5a6db6c5c398a9bd140ef56580a7f3dc73b57824cc741b788612da74b9408e456959e7f3c46adc94890d3fd6553f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165704);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2022-20870");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy16234");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa68343");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-mpls-dos-Ab4OUL3");

  script_name(english:"Cisco IOS XE Software for Catalyst Switches MPLS DoS (cisco-sa-iosxe-mpls-dos-Ab4OUL3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the egress MPLS packet processing function of Cisco IOS XE Software for Cisco Catalyst 3650, 
Catalyst 3850, and Catalyst 9000 Family Switches could allow an unauthenticated, remote attacker to cause an affected 
device to reload unexpectedly, resulting in a denial of service (DoS) condition. This vulnerability is due to 
insufficient input validation of IPv4 traffic. An attacker could exploit this vulnerability by sending a malformed 
packet out of an affected MPLS-enabled interface. A successful exploit could allow the attacker to cause the device to 
reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-mpls-dos-Ab4OUL3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb18303c");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy16234");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa68343");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvy16234, CSCwa68343");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20870");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "3650|3850|9300|9400|9500|9600")
    audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
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
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.5.1',
  '16.5.1a',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.6',
  '16.6.7',
  '16.6.8',
  '16.6.9',
  '16.6.10',
  '16.7.1',
  '16.8.1',
  '16.8.1a',
  '16.8.1s',
  '16.9.1',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '16.9.6',
  '16.9.7',
  '16.9.8',
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.3.1',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.4',
  '17.3.4b',
  '17.3.5',
  '17.4.1',
  '17.5.1',
  '17.6.1',
  '17.6.2',
  '17.6.3',
  '17.7.1',
  '17.8.1'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['show_mpls_interfaces']];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvy16234, CSCwa68343',
  'cmds'    , make_list('show mpls interfaces') 
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
