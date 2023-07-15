#TRUSTED 54dcfa245abab080113eedce88fad996a323bf44ec99f02a9169762144d9291a318a063973a89b304aa1f68d69559418bbd900b4c1dd077b1aa143ff3bf9b7517a79857987e6bb479480acb29c376537fae069f68092f723ce34dd99dd257cb5d42ae2c009113622026faf685efb0ca2bdc0e22dcaf0ed624b11037d6f9c5f04b2efa1842fac43029118ee5d0c0c33fdc89b467742e995065f5cfaee0c32b7ae87c17e2e3c2be6b62550c9785eea6ece8df1d39bb79adf4e8fbe1116df0ab8b9620beae6d747195c9d8076ea4126900453b9bbf8c8fec06b304c6fc453fa63869724e293fe3eb95784fbb27116f11fda2670ccb2cdd7ca59faf0f2d1a2e66bce35e43202cadadaab2916567ab10cd87f304363d9eab087b3cbd18cfb201da0d334794a4133ec6cbfd0555d18053121016f199b76a7f257caab3efeea2f6fbbe6af30872e25f0bece50e1aeca2cb4225aa5d351485d0858db71fa2694e285f568e024b39cc7e2aeed598468f5eb7e7bd02cb5d693f6659d6caffd5957fad2840804c46d6fdf630db732221428ec163ef20a4d267fc09d7c507f74425441bfdb2e76261ee8f28c4396635595056d3637d5d066359cf3abfd75e9eb9e63829f0fd1b2f502f8f3cfe8e2b04ac84eabae1cb7f5f2db8bd2541a7738e579655531aefb2eb5d58ab92aa85b8e8ddbb78d928e9d91085463a69ad35f78b6dde31d10cbbe
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148327);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-1431");
  script_xref(name:"IAVA", value:"2021-A-0141-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu95283");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-sdwdos-4zeEeC9w");

  script_name(english:"Cisco IOS XE Software SD WAN vDaemon DoS (cisco-sa-iosxe-sdwdos-4zeEeC9w)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by a denial of service vulnerability 
due to insufficient handling of malformed packets. An unauthenticated, remote attacker can exploit this by sending 
crafted traffic to an affected device, which could allow the attacker to cause the device to reload, resulting in a DoS
condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-sdwdos-4zeEeC9w
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e861716");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu95283");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu95283");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1431");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

var sdwan = get_kb_item('Host/Cisco/SDWAN/Version');
var model_check = tolower(product_info['model']);

#Model checking for IOS XE SDWAN model
if(model_check  !~ "^[aci]sr[14][0-9]{3}v?")
  audit(AUDIT_HOST_NOT, 'affected');

if(sdwan !~ "([0-9]\.)+")
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
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
  '16.12.4',
  '16.12.4a',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_version']);
workaround_params = {'pat' : "Router operating mode: Controller-Managed"};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'cmds'     , make_list('show version'),
  'bug_id'   , 'CSCvu95283'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds  : workarounds,
  workaround_params:workaround_params,
  vuln_versions:version_list
);
