#TRUSTED 8fd10404a1f75193bf5d9f5f95c971fd5e3e8765cd5977dd7b5fabd9b6a769470432c80d8136753fd65107135e6856a275a174e671896b4b70fb989a3b52265d71ef18d587f0622dc6492e1fc74d4854749be8ed26cb8ff6d4ba43728ce40f0d89781c2c9e32d9a95b8e63de47231f86e52f8c6ad95ac2aedd7fb7781db2a00c5893ad6059ed4e157e0966bcb0e6a2db22eb7b301aae18d915ce7739af899594f5fabcae905c01c06b7a6f4db2876084130d41d5da9bb2e5bf8b0a3098eae3fc72a0ff1e0db1a44b0721c4bb61086af726464d8f1c726d0ca47840a3635e9c2bc2a9442076a0da0f479db08c01ee4978ac4d27c82698034d4642c34ab14ef8438c960e8e1f8d9ac5cdb6cc4458d067f61027adf89b09aefb5231d9c623bd1a9d29d9a1bf5c1cdbfb2280a83dad3ba0c9841b0d257130ebe5bd044bb1a2ee91c31bf9f833f81d0492ac3be3eeb0b5b67b0b3e606f1cb24715349dd3dcb5655bb153e9fea0cd2e5ce315318366c4ed8e6756ead373913f8253940be558e00cc5c1e97ec94d08aaa45dd038879751b7b62514fd91d76f02b4ddb2fd008bf09b1a3b7dad16b4d72c4ef4b05b47490a5a9686207b0fe224503a59d6363ddf75553119a880bd79bd1f58bd07600219dc64804657942a7c39dc0ea20edc56d7d8a088af5b786e477366a9a9a098533e7ff529cb9dfb2cbb638a537afbcb370919f297f6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131727);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-0484");
  script_bugtraq_id(106560);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk37852");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190109-ios-ssh-vrf");

  script_name(english:"Cisco IOS Software Secure Shell Connection on VRF (cisco-sa-20190109-ios-ssh-vrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is affected by a vulnerability in the access control logic
of the Secure Shell (SSH) server due to a missing check in the SSH server. An authenticated, remote attacker can
exploit this, by providing valid credentials to access a device in order to open an SSH connection to an affected
device with a source address belonging to a VRF instance, despite the absence of the 'vrf-also' keyword in the
access-class configuration.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190109-ios-ssh-vrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efbc26fd");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk37852");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvk37852.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0484");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '12.2(60)EZ12',
  '15.3(3)JA1n',
  '15.6(2)SP3b',
  '15.7(3)M3',
  '15.8(3)M',
  '15.8(3)M0a',
  '15.8(3)M0b'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk37852'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
