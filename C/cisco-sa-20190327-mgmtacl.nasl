#TRUSTED 6586e3afb71572649acf0a1a272617f59a37b10fcb1d07f5391f59b33c322a162ae0862ca8c4622a9db36d5bbcf6ed92df12daf2de791ba72612a9252361fe21e56d5f01fadf5fb31e4bceb8c43d49578367d3c344ba8d47c95570c6ca3397005963cf9c32c12e3d98d8138b860634abc22d1f6da8f8fd46b7cfb771e8708b48b55f32c81aebc735aaf774f87a37d6e02537738219a7d923ed526b43bb2850d1e62de1c91320fdaf58cb574027972df4bed765a512a65d5261b5f46d42827c465e06b6fd16e1d20cf75df932e5beec9f8304e4867699968729f1b7fdc3b28882557b3573189489bce3275dea5ebd89639d6b31895afe78794e7fd87354d975f1e801396ce5028b959caf1199f83eb963221c50bdeda006a6bf476931d9eb47c400082b140606222926500650cce144d52831a023cfda978bff512e7c1864128a588ecd0257c5b92384ccf851ef22f5e1376c2682567fd53a3dd3d1cec2f6e483c8ed981c000aa8ed82f6f360388798535ba52811afb97d2f20c04d796472a1e3e01302ac6339516b9d7a0621deb7304e202e34b28c4af4c0e2aed18ac5042b9ccd339f709a5b553229e55d03a5719f7257d7f43b043a774f089669402ab2834911fb4ed953fc0b0432de86fba546407d87309764e65f7f294338d82ab72ec47e00baa7b2bdb9971b9de8d1aad495f88113bc992a8442e8e99825686d43b0dbf4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(123793);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id("CVE-2019-1759");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk47405");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-mgmtacl");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Gigabit Ethernet Management Interface Access Control List Bypass Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in access control list (ACL)
    functionality of the Gigabit Ethernet Management
    interface of Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to reach the configured
    IP addresses on the Gigabit Ethernet Management
    interface.The vulnerability is due to a logic error that
    was introduced in the Cisco IOS XE Software 16.1.1
    Release, which prevents the ACL from working when
    applied against the management interface. An attacker
    could exploit this issue by attempting to access the
    device via the management interface. (CVE-2019-1759)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-mgmtacl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99f4882d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk47405");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk47405");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1759");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(284);

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
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
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
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['acl_on_gigabit_ethernet_management_interface']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk47405',
  'cmds'     , make_list("show running-config | section interface GigabitEthernet0$")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
