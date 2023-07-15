#TRUSTED 18013e006aebc7455049bab7b642854d4c389b837548f41a0920ae7c2d382b2e0c6c55e9143f2a0b623e4a47b9a17a5841e45341789a28cbb451d0c610b7c691866fe7875513ff99f59ae1b8c5111afd119d2547e778d900fb09e9067bcce076484d91c13ac416a5911e48d2fc8eb4e5004f7e3b0fe7c9ceb6c779a7b747ab3aeb98a7f4945cf369a18186223811d0a7e9bac31053a0293352a407efa5e897a2dee9ae79c999dbeb9c67e5927524c1a9e0a270e24b83726d836a98ce42ced6540c3b7bd1056e2921c8b3435687106d0c961a88e76a1d866d6ea1a03f90fca6c6b8556881cc7f2197fa585ba5c1d406ba7c65217402f1c8c06e27365200c0e51a4b5424bcfc31237ea5a171b5afdae4f6d0627ef667ca36b61005cab3de641a4e129d2a575d08ef1ba1e79e2df0c760b5d484a5dec2d28e8476b158db802cc092f076c508e7bb28d32b72cc31727266f27b67500a2551decd2a87e5439fffcb430b6a7da24203776503ed7e22010f1e9fb1e8577907eb3663be8e20a09ded5963e0401e45b5d41e86094164e64a1d336fa75e776af86419a77188e74ce65bc9781353b37fe0ac60f845ef849f16924950a6044d887eec5ee76ab01aa13bae87881e5c741fa61060727a46504e4e0601fb67a9edab20d6f43048581b9cc5c901814a2c6abdd2b59f6e044b041d6fb9958f7c881d4354fe4258db5e6d603a186250
#TRUST-RSA-SHA256 1c9b618f30d387ddf2e3f1f9390a868a209448a25c9ab964786231d25a3077fdc5a4785c115ce1d757156492a5f57cffcf3ffb8bd9c3f41a6e8047f6d39fe2c182f57e589f4ced47679a6baf16265c25d3ad5ef5d398e2d0f74dcace548541d8f23fd73060d6dcafd310113ffe81717b05d8173c1c9ffa24dce0a6e83a5f6a212216ececdf951ba462d314c22147da0cd4c5e66f4b7b1c3973934535a4d813452b779dca068f2b651a15442ec5d16735649bb561c8aa5ca4c100b3df49ea0358d3e790c80782c12f776ef202e85e293996034d2dfbb5d7592f7112bb7bf938f70eec6406b22cf744c877bd6f08673b38f08b3ed8b48fd9fb647c999390294143c30ec6e0f5e67bfaf5511ad14af611d842a851dadfb99740dc9d54c618f8b5c594dbb0005d6c3a3fc653008d79821140798aebb59218f2f9c3ce04a2ab19436ff47efbc45e5a741cf917efde2d23aaf16f0570fb27b80423ad692aebd34da334adf8c3d72c4b20b1be408dbfddee3ef41ed0944db77333f675cdf22b4cbc4bd96a42ec784f1343271af52f1fd7bc78749e3ad1a64345fa728d6c7e0f62b92993b9f6f90614e5086d415502f3cf77af8f76c596e96400ff1447d97f4c1d2e8eabb74afe630d1b01236894821971b9b706a41492c3acc2546580e3db2c02d7f44aaec5596a536f51848257df7c5806e156c169894afb062d29272070f9987374e4
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166015);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id("CVE-2022-20851");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz74822");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-cmdinj-Gje47EMn");
  script_xref(name:"IAVA", value:"2022-A-0390");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection (cisco-sa-webui-cmdinj-Gje47EMn)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web UI feature of Cisco IOS XE Software could allow an authenticated, remote attacker to 
perform an injection attack against an affected device. This vulnerability is due to insufficient input validation. 
An attacker could exploit this vulnerability by sending crafted input to the web UI API. A successful exploit could 
allow the attacker to execute arbitrary commands on the underlying operating system with root privileges. To exploit 
this vulnerability, an attacker must have valid Administrator privileges on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-cmdinj-Gje47EMn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41961c8d");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74745");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz74822");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz74822");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20851");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/11");

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
  '3.11.6E',
  '3.15.1xbS',
  '3.15.2xbS',
  '3.18.9SP',
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
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.2'
);

var workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
var workaround_params = {'no_active_sessions' : 1};

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz74822'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
