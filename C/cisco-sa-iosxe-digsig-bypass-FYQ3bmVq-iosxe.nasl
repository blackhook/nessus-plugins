#TRUSTED 0e51bc726a065f83b666306e19bf1d372912a79acf614b58833d18ed3600ff492315e2f0576dc19575490abe260472a1e69416fb5a960be210b914dbdb8390b4c2241a776d4a413a960621a92957d32c4fee6433b4f37fc1db0fa19d917da071904e799bab95b6882c152ea6d8a01ccc81f44753da9d2bb2b1f6532a23e383913c3de1ac6ac4eaec84e8ef26278a55ec90ccd778638b784bdc2f987feacad5f52855c980c0c2411e8b00986d07548369a151680594708931aa11a922ebde2c5a2c4aa8048fbcdbee7d0002e061ec7e646534afd68fb2b3d38f7f88a3202685fa9d7b26d14526389573301c40e1115c677d2b65c001ed7498d35a60e3b85fce9bdace8c5926e055c8ab6c58f775d9380b1cc921cbf5d7fecf189428dbf7072cffac482525f773b2d10aa330259d1fae5e7e2e657b0c6751a2ed416c16daf6bc5c3c44040fcfba8779fd7b7c216348885be6dd5b9584922cbec34825aca6d94a09f401a93c98cfeff27b2ecf991d0558d1c7fdaf179f11cf6b24c71882d14e15fee7a54dec1afc024ec068c295d62299d42fbed8de8c2c3744e253a584a37dd00095e320606478d0357930f0c1e25f5fc40931db37758c8dc2528a18052694f68ebc9f26e8ed3286b6294706ce0ded6db56a9a2aa620154753fd3a11214ffa3008911adf8bcdc824a8f60b86f4e75aaca1ec822b00311ebfd5bcc169e6730771a5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137148);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3209");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk61152");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp77508");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-digsig-bypass-FYQ3bmVq");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Digital Signature Verification Bypass (cisco-sa-iosxe-digsig-bypass-FYQ3bmVq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability due to an improper check
on the area of code that manages the verification of the digital signatures of system image files during the initial
boot process. An attacker could exploit this vulnerability by loading unsigned software on an affected device. A
successful exploit could allow the attacker to install and boot a malicious software image or execute unsigned binaries
on the targeted device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-digsig-bypass-FYQ3bmVq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?feccc784");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk61152");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp77508");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvk61152, CSCvp77508");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3209");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0SG',
  '3.2.1SG',
  '3.2.2SG',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.2.10SG',
  '3.2.11SG',
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
  '3.7.1aS',
  '3.3.0SG',
  '3.3.2SG',
  '3.3.1SG',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.4.8SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
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
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.6E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.7E',
  '3.6.8E',
  '3.6.7aE',
  '3.6.7bE',
  '3.6.9E',
  '3.6.10E',
  '3.6.9aE',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.3.0SQ',
  '3.3.1SQ',
  '3.4.0SQ',
  '3.4.1SQ',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.5.0SQ',
  '3.5.1SQ',
  '3.5.2SQ',
  '3.5.3SQ',
  '3.5.4SQ',
  '3.5.5SQ',
  '3.5.6SQ',
  '3.5.7SQ',
  '3.5.8SQ',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
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
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.8.7E',
  '3.8.8E',
  '3.8.9E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.6.7',
  '16.6.7a',
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
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1b',
  '16.9.1s',
  '16.9.1c',
  '16.9.1d',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.4c',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1c',
  '16.10.1e',
  '16.10.1d',
  '16.10.2',
  '16.10.1f',
  '16.10.1g',
  '3.10.0E',
  '3.10.1E',
  '3.10.0cE',
  '3.10.2E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.3E',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.12.1y',
  '3.11.0E',
  '3.11.1E'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk61152, CSCvp77508',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
