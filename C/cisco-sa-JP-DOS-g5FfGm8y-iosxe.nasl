#TRUSTED 78f63c027964c17455d6bacf922a5f6c9f6ec8bf32c172e942549d1311c6193505a6c3246facf3eb266ee5955a8dc0202cb016d96f466b9dd098155929c537b9b2a99dc12e15d0080c61cf245d5285fb5702f62058946f8c5ddb4856a0e2893b6a5ededf13350628f292a3eee37e8e4b8fd073f19839394abcd517fee6251d905abd4e1b9416bb833675edea29b45e33d344ebd9ce905c201575a9b32f67dea015876242d4a075577d376b5515808e602b9053c09de09db32ec854530b5f8e426645efdcdf3ac8858767ac2160f6e99e16ae8624b25610dcee47f457c17c1fb9a3d7276c32eaed109c2dc7b7eeaa623c051f4de79347505838ffa2f70267bba0b8ab3918f632eadb3956f09d3ff9eada76e75d87045f9b55a56d315a0f03b35c82d579f033dbbd92ca1a3472509872813e92d3ea0c2c7f85e5ac0d61b3857bbd4f11ac7966fbb94066e06da2f1932888c943f8f9bb22c71aba8025162823f7813aab68084fabac21b46f2f8478b6ee233672357d30a6ee20c6da0246973fe2ae6be60e60d845ff24d19af5a57afa03366b8285282e1d7963bd191374651d9d19d3669882adaf9b5c0014017965f2b2d2d9372f5d2f791164fe7d80fb695878ecd630687c2200b3e9ccf1f1fcb85dd137dff9550a99832601b5b32561821b3727f1f5ad3e5663d94e8ba00a92c6f091139c38d5763aeff76b27e2239a53d302eb
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148951);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/26");

  script_cve_id("CVE-2020-3527");
  script_xref(name:"IAVA", value:"2020-A-0439");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr37065");
  script_xref(name:"CISCO-SA", value:"cisco-sa-JP-DOS-g5FfGm8y");

  script_name(english:"Cisco Catalyst 9200 Series Switches Jumbo Frame DoS (cisco-sa-JP-DOS-g5FfGm8y)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service vulnerability due to
insufficient packet size validation. An unauthenticated, remote attacker can exploit this, by sending jumbo frames or
frames larger than the configured MTU size to the management interface of an affected device, to crash the device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-JP-DOS-g5FfGm8y
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e04a5a3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr37065");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr37065");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];

# Catalyst 9200 Series Switches
#   Catalyst switches don't necessarily have "cat" or "catalyst in model or device_model, but the only
#   things that come up when I attempt to search for "Cisco 9200" are Catalyst devices. Should be safe
#   to just check for 9200 series.
if ((model !~ '92[0-9][0-9]([^0-9]|$)'))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '16.9',  'fix_ver' : '16.9.5'  },
  { 'min_ver' : '16.12', 'fix_ver' : '16.12.3' }
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr37065',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
