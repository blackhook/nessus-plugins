#TRUSTED 9d4d2ef821599d2c17f4027337a0c5ffd7a27c434d00d4ceccbcfe1a4f6fad9a555d9bdc7ff9a11cddf8056f245ef3f59433be7901efbf95e2048a9be47447fcb83ba195d18e71440ec8c75ad8d1f727cf80083f4d31b358eb53bd348a2b3edb87504c58572e9d32e2131b86fbbbe5c45334acf1d176bf8b1bde32285f517773e4cafc2882321a692bef97ee3d3b733e135e502ceb569b5d03af805c8dee52934ab35bc20a8df31d13ff7c39c73d91e0afdb73f762f5295330f0a5a41b8fe938e522ab38728670ae3bdc9ac7ee809c5cab07b7c31ac69ede8004cf5f5e201353aeec84fba23b99270755ce187ad519b7513ac922d916b7a8cc85a9d9ba07b36ac596278591814994a8578f312481ae3ddea4a8e7b891c64e7fd4e987c12f7769b30c3030aa53934ceffe74cf85e6afdc6ad33c6638f429c9783925b09b14bc8feb1545d61b21d2622921f8a74dba50374698edcf53bc82cd0e31f3c1ebae1d93a7e5ed898e8c8111b29d07a29ae1db8e65859dd75c07b4f6bdb1e246230c1d0489f8c9ef2ff3910d7c5129bf901318ae22213e23478522825efdc46f287f72e9ed0c32122ca5368eeeda7a635c2b7b60468ddce34ed10a59ba0706d320415fa26b84b75aee054a5843fde898f51da4f0e79d4cc9f47eabab32c507b147e8591bc1a82e448e92486949b84bb4a0b4a83ffd32dc8bbf368b51d33f52d24d0d53d4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129713);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/28");

  script_cve_id("CVE-2019-12648");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm86480");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-ios-gos-auth");

  script_name(english:"Cisco IOx for IOS Software Guest Operating System Unauthorized Access Vulnerability (cisco-sa-20190925-ios-gos-auth)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a vulnerability in the IOx application environment. This is
due to incorrect role-based access control evaluation when a low-privileged user request access to a Guest OS that
should be restricted to administrative accounts. An attacker can exploit this vulnerability by authenticating to the
Guest OS using the low-privileged user credentials in order to gain unauthorized access to the GuestOS as a root user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-ios-gos-auth
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?378b51aa");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm86480");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm86480");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12648");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');
model = product_info.model;

if (
    ( model !~ '^IR8[0-9]{2}([^0-9]|$)') &&
    !('CGR' >< model && model =~ '[^0-9]1[0-9]{3}([^0-9]|$)')
   )
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '15.8(3)M1',
  '15.8(3)M0a',
  '15.8(3)M',
  '15.7(3)M4b',
  '15.7(3)M4a',
  '15.7(3)M4',
  '15.7(3)M3',
  '15.7(3)M2',
  '15.7(3)M1',
  '15.7(3)M'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ios_iox_host_list'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm86480',
  'cmds'     , make_list('show iox list detail')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list, 
  router_only:TRUE
);
