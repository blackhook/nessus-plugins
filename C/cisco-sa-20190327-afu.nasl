#TRUSTED 50b4772a98ab156efe760ea9bf912f3d9f3e57f11a480a7c6bff650e5ef817dffbcd36245405fd9a1ebca9fe232f847e7ae3fde545363d48ef6443d017d32459c82d3ef4eabd7840064ab97a3e3e3844e3d6bb1dccdf6009eff7efb09d768d611002d5c49e059b1ae79903ed0ca6cb9f1481e8aa98270a6e422b0dc97e3f5bb29a543eb4add1dfb6e5e34eac410bfad620a53cef24d9d049d42fcd4f5efa1447f8cde2e08a456701079148ed99b9449f440178b43f301cffc8f692d30711973387db593f828eab1b5064516532e3e916cfed8be2b97e07b49242a351befc8dbf9cb80c1a46724ee8f1b5f582e1f13d6ad75ed5ba46148de93f0182957f96246256489fcca1cf27b4557c645b289a6d224611919e7a91ca3c5327e16a8d63105801aff2d86b4139431cdd86d349e582f8593e5020702a208cf748a75d59ebe7f2422811549df2dd7d43cfc853692028e66b6de21ad5a67ceaa4a4914663e9cfd87ba80cffe474cfa18cf09f332ba2c705bb6c46a3d5425ae365cb0f2eedcd7b97c7dbb268c3d4a2b19967c7d8c4ee88dc314f1153d78d996d33f483d3d6fe89c29397be72fa9363fbdaf1dda0ee5ca0f8145d8590fc11fc5f6fddb12e5349c9ab893a21dcb5201d75fba40dfa95075a416dde25ce5c5b082db396fd0ab28b74f6514b8d919e490d148b35086ca9a39a669a1547ece142001408b31fc4292c4166
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124589);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id("CVE-2019-1743");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi48984");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-afu");

  script_name(english:"Cisco IOS XE Software Arbitrary File Upload Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the web UI framework of
Cisco IOS XE Software could allow an authenticated, remote attacker to make unauthorized changes to the filesystem of the
affected device.The vulnerability is due to improper input validation. An attacker could exploit this vulnerability by
crafting a malicious file and uploading it to the device. An exploit could allow the attacker to gain elevated privileges
on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-afu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f275e4c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi48984");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi48984");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/03");

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

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list=make_list(
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
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

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvi48984'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
