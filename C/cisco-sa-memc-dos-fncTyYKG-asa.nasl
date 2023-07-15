#TRUSTED 982ef6f6ad3311ffa717f8d64a6e22c67b222f8deb901bc138a14daa2f83cf7ea62019b9b6107cc73e4995284128b38b46e125d39a968fcf498cb8c12807c5e3442af4787cfaccc1e60b015ea62f827db317ea62a52069752e41119de8c2a9c194e34f680d55af4ce3bbe9156fea80f7941fcc45b9d123e754d6f3e7a47300d685e09a42a1eff3cc8ae0e652ee62868eddd227a8546a3892fd8a95fb51f3e6d8c816840742b1ae7283a3262431f0b28d4044fa237d9818fbf50d77bc5c71df476fe4024a0168238ebbf8895b98294fcae5f8e04c73aa3bed2af1f846341fc860d176c211789b582385848ae97bdce78ee998130aa376a34bae0f026b5eab8d38f2e575ec4352b64080ecb69f305b85e2eb83db976f6ba16df62676dbacdea9aa8eb2292737535898f3d4a4bffc462a4dce279e74f1d9dd017333e691b938ea11fbf4df4f168e257b98a8030bae68ca0d72cdcfe861cb0f0dc560d4b4526f279c0ac82c6648d6c5dc5f46a930fd4fd7429d4064c61ce3dad98cee4407697fa65aadc581cd0a6e3ef42a2aa8cfed4e5347496f287bcc9c2d4fde1e59b5617df583b335d3b6db466e164420193e51d16039becf241b9d8a36fa8284f277363ff3aff90fe56ea8248ae26704e5af52608f8fd82d133a4f7118511b2f73f46b9ec10947f07593a62b3cf3f16e24b64988c35fd75a66d88796868a99a3fcfb780702be
#TRUST-RSA-SHA256 06d31f1c7ed3b055eef6ec991bece7cf5b454e43f4bcae7e0f3d1071473b0ce8f14ac786db915067f5b32d5ea08860ee459b6d6aa2deaf5a78ee3c3d8d8a85a2b8fbaa222a6dadfc2b1715b60ec274f094f7d2d8624cca8f5ee1f34e4a032f61e98202c264193cb4ea12f78a65ed8193020d46d3affdd1d7f529e49ef8bd4163c5d32253ed09a770a75a0f3e2f11446437317ee8ace342c4530e32a0c695b1b8f91468becec5fb7055c9ec7f05a5debb68d6e62dd80f6f1485a9d715ac4618f3611e04b90ca6052c38afe6be5c2a21489bda677a7f07972593bfb70c0aa37d7feb9cd21470c8b26060bda979fa27085d4ed819993eaa8ce72edfec59e496fd6cc268eb9e34c933db9c056cb594580bcc3da05303326f523aaa53d0088b2046cbdd976d7637d91fb5b4da59922c7c9668f57ff49b354878c5c02b405e2bc7a34ac6ec74bac261a5709edc2c38b05f0cfc99d1f8f294f5d659f8d07ff180a6c2ba00c2468986b65f36cb2689637b9a783d6b142e9aba46c7dbb1a8ca9a595a2a544c60dafc8ef31b3426edbe0bd7912db30f6edfe1522e098f90dd174ed1a8f3e02ec2375cf50479e70eb314133ff0862de718faf4c555ec9e4e2edae267ffc918e6d4cc908649322c00cb034a653b0af81ee00e866cdb3adc3c9cf76bdc976933b64a00fd22d2299052a1e505d76e8fb3aa1903a7b24206b08f10d9f7e583d5d4
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149299);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-1493");
  script_xref(name:"IAVA", value:"2021-A-0205-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw52609");
  script_xref(name:"CISCO-SA", value:"cisco-sa-memc-dos-fncTyYKG");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services Buffer Overflow DoS (cisco-sa-memc-dos-fncTyYKG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability due to insufficient
boundary checks. An authenticated, remote attacker can exploit this, by sending a crafted HTTP request to the web
services interface, in order to cause a denial of service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-memc-dos-fncTyYKG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4d5076e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74594");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw52609");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw52609");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1493");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.8', 'fix_ver': '9.8.4.34'},
  {'min_ver': '9.9', 'fix_ver': '9.9.2.85'},
  {'min_ver': '9.10', 'fix_ver': '9.12.4.13'},
  {'min_ver': '9.13', 'fix_ver': '9.13.1.21'},
  {'min_ver': '9.14', 'fix_ver': '9.14.2.8'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.7'}
];

var workarounds = make_list(
  CISCO_WORKAROUNDS['anyconnect_client_services'],
  CISCO_WORKAROUNDS['ssl_vpn']
);

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw52609',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
  