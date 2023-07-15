#TRUSTED 1db16382d842cb5f6f69f041ff03f847b41c8fdbafff649970d2a2372c7432e2b8ddbecee115a9e5fc46f1cff7e780c460994ec6e83a9adfa5e184622a971b9e84debe7d1d584dd1d90fb31914f698119f6d368f04c56b29b6d523f92fd5a555fcab2909c1afcef232260fd242338a1f1655b9e294b541516a801eafef7a66318ee2b09e8f88b615af90c2fc9e08b6bbe13157ed6acf7a992adc0f9031181aba546829b5d83a4afec23a62e1698b22cee89a84d5fca73d8c6b11642c8a83b3a00486fa687dd2af06b02548dfeb1a322d737e7b2d13fab767a40cbd86cda6899df3a352fd0497d92844c679677f2fb14bbaf98d0966313fdaf3818a7a1a768bac46b91a2d41d4fd24f88eb79c6d7885f12df86e67459c5a2af35a7612e4f0a5c661c0ea7cb1f653f6f11c20b9c6bd65230c838911da6c0aaca7f509f5108c62b94d828efa0c5ccb81050a1552cec0e75964235a5f66cfd046eda51f6190d4263b36d824e5f35d0c739b84c6669dfa17fe9a333d00281e79313d9ce49d61ba73d03bb7e7e2497c0ff6b8377bb3d8b56b1909840643a00baf837b12139a46e00807b8f218a054f4cfbf909a5c291f891d3ea5fcf7da2a21804093415f95b619752ce34db1f37514a58339df1b380a4c55f40fcfb07a3d7d0d2f155785f8295c9c3369bcd3d1c22a10a9b59803ca5a12fce4b2ddcca08665728b3d1e69e7726ec131
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148098);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2021-1394");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm96192");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ncs520-tcp-ZpzzOxB");

  script_name(english:"Cisco IOS XE Software for Network Convergence System 520 Routers Denial of Service (cisco-sa-ncs520-tcp-ZpzzOxB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ncs520-tcp-ZpzzOxB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42f2c43b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm96192");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm96192");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '17.2.1v'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['HTTP_Server_iosxe']
);

workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvm96192',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
