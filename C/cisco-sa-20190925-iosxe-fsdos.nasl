#TRUSTED 3fbe851398018642f1ac2e228a9eb0e114160f897941960ef35d6b3a2c32c3d8cd424c216b32d42fe454e7565712ddfb81b4b7e442585b997a97c74e36e5d0e1b543cc1319876a519c9cff8165f046fc23f51ee34755c236c8f851edd0d865d496f56c3d5a81b6206b82124080441f67bc6f52307c2bae4150e1710f16f2914f43437461ae1fd1093e09197a4cfec378e567d227c45e700fe12e5da32641728ef3c9366e86cec1607a93ed68158fd5d6a9d95ee2eed3ce688b253464a320790d6d6a8a7079e3a46a47ff92b3f1257d00a825eb919754599574952660febea1fd5a9603da15d9782fcd2ddd49f51a620c97c6488fe951a0b7aec2d0e92d7807ca9817d09f5a2ba0b0cf7ec088589a9aef8947231aa5bbe3052350ff09e86a2423b14a49118fdf2b81713e14bde13dd7f11083009b7eefaa29448b85c4b8789fe988f867a87bdecc7f5600c67380bb7af08d4a0612a9401715503c3e0c954849955b904590bffd46c78762ce83fedd78348bc48fff7a9de452a04db8dff57b403bfdd264d73d8e8a991c5580d977ba8ad74f61772ed630b30ec5be2b357151041dc57bde1338196f0c3d43d9d452fac1242f2ee116a0590a5dd752b322322886960efc0db67094dee791aad19b2798978cfd6b0f51459383e39838f27c3c3c83c0d1853831ace3254af757e5ab89e1d12cf1f2cfb3968ca194be726a05b6733703
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129816);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12658");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf80363");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-iosxe-fsdos");

  script_name(english:"Cisco IOS XE Software Filesystem Exhaustion Denial of Service Vulnerability");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the filesystem resource management code of Cisco IOS XE Software could allow an unauthenticated,
remote attacker to exhaust filesystem resources on an affected device and cause a denial of service (DoS) condition.
The vulnerability is due to ineffective management of the underlying filesystem resources. An attacker could exploit
this vulnerability by performing specific actions that result in messages being sent to specific operating system
log files. A successful exploit could allow the attacker to exhaust available filesystem space on an affected device.
This could cause the device to crash and reload, resulting in a DoS condition for clients whose network traffic is
transiting the device. Upon reload of the device, the impacted filesystem space is cleared, and the device will return
to normal operation. However, continued exploitation of this vulnerability could cause subsequent forced crashes and
reloads, which could lead to an extended DoS condition.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-iosxe-fsdos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7c8aa37");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf80363");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvf80363");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12658");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
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
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.1d',
  '16.8.2',
  '16.8.1e',
  '16.8.3'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvf80363'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
