#TRUSTED 5bfc865d3264c990d26e804c4777f802ba46df4bd09b5be13f1fe17d27af95d3dd7fc1d3e0481a9766ea7bbf468aa3fa179af267274fa62cf3809b85034550e9f668ac24f8056a6e1d16ab4e5bfb54f2a7dc67d27d98a2eb2295b24492eb535564765f8c78ed66c3c869509af9b62133a3af82c354fda8c73c5a205cb67e401e42acd5945a0668d40d91645d5a6cbda86224c5da1f4a63d209bd61757266275f30bcf1a157c5d7b3e152ac62eb25d3d9d05ac529e347033819c509ba12abdaf3981df7f25aaa0002965ec0a3384555d35e5e7ccc9c49dc72d5a5faacbec176cb92a108f3d5cde4be3ea071a9425c0be2e5abc2af09db9012e4dd8fa8eeccdddc834f11b169ffae7e10ad31dec1b4776c9b6120bd42735786cadde3682ce32fe95d26ba73b2333555a9d0453e248c272d034b9dd72870485b09b914e5a16d96f6f3b196d7b55be31619ffe157885c17606189273295678b6379f0233574611f22dddc962c6a129cf27e97f08616809b9d448aad6174311c08c59497c57666655c96cd88b88e6c82cbe25134fbe38cb1375cf372c96e6cd40882c06076bcdecd55b08527dd06f82797f5dfa57d28acec55c591c94d7cb4d794f3f2c67f02833e431f1adc6014bc24f653d8c8e79831f737e78d2fcaf0fed7dbe4aef909e7fe4279532a3fe406fb4089f1897dddd45f702156adcc901d24fe2286651a01bc9748db
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130763);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2016-6378");
  script_bugtraq_id(93200);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw85853");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-esp-nat");

  script_name(english:"Cisco IOS XE Software NAT DoS (cisco-sa-20160928-esp-nat)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the implementation of Network Address Translation (NAT) functionality due to improper handling of malformed ICMP
packets by the affected software. An unauthenticated, remote attacker could exploit this, via sending crafted ICMP
packets that require NAT processing by an affected device, to cause the device to reload repeatedly.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-esp-nat
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c3c8ff3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw85853");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuw85853");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6378");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

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

version_list=make_list(
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.2aS',
  '3.13.0aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.1cS',
  '3.15.2xbS',
  '3.15.3S',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.17.0S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.5.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['nat']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuw85853',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_versions:version_list);
