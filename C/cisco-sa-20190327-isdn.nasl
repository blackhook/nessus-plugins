#TRUSTED 849441fe5ae314b8ff145da9ef498061bf8ee3a9bdca7cef9382c320c47613e0654e7d41731cb80c0776af1b5952c07f930b233be8dc2372ea9e967095992641800800708d3ff7fb7a06fb0113f1ec02ae89f87e9c0da3986476bf3aa712d00e2eae9a63b041e40584316b604953924e8e9f6c13cb328b80a1f0ae0c2f565aefc6ed23e3f26ad628e45572ebbf4bb590b219a2eeddb3a9b998badb70f7a9f841dd074be9c2cdf19d5f4f6b151671237ab519d2e649ae1ad37e96dfda9ca381c0068f40f20dd233beb36112999c96d9e2dcdba6e135d9f7a5aea8bcec7d597bac35c8351a397b80da144ffe56571fab920e866c12f5ad60db74c373aece3d9285f836e8cd33befcd90680ef02eadc80dfb56b4865a75b45c08afb42d391da12a4122a24ada12da75e6ea8143f88ea6af1b185e211dd512161c65b2ee9721efd8c76408ca37157ebfb97e0794456aed2104a6312c961929c145fc9d3fc9cf3546cdc24b105433385e8843a5b57f951ae337eae0dbffa06d35f6ea9853c8c2947edfdff1761a34d6b32a145800f139f304b98d897964bde0bb74b06900113dcfc84e79ce3f54f50cc68be166e3a87e734e46a1487087e13d87ec5393e2ff49968f44fe13b8d199a5fde9ab330dfcb5fcefdbfa0a641db6e6da3f5f787eab9490c7ae6d846774dfb2be7bc37c13853f9c745e4e84f092bf7b8ae365e8960a0882451
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128421);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2019-1752");
  script_bugtraq_id(107589);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz74957");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk01977");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-isdn");

  script_name(english:"Cisco IOS XE Software ISDN Interface Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the ISDN functions
which could allow an unauthenticated, remote attacker to cause the device to reload. The vulnerability is due to
incorrect processing of specific values in the Q.931 information elements. An attacker could exploit this
vulnerability by calling the affected device with specific Q.931 information elements being present. An exploit could
allow the attacker to cause the device to reload, resulting in a denial of service (DoS) condition on an affected
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-isdn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6adb46b3");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz74957");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk01977");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuz74957 and CSCvk01977");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");

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
  '3.9.2S',
  '3.9.1aS',
  '3.9.1S',
  '3.9.0aS',
  '3.9.0S',
  '3.8.2S',
  '3.8.1S',
  '3.8.0S',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.2aSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1S',
  '3.10.10S',
  '3.10.0S',
  '16.8.1s',
  '16.8.1d',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.7',
  '16.3.6',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['isdn'];

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCuz74957, CSCvk01977',
'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
