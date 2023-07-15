#TRUSTED a73a86e7c9efa6da5ef17bb25f2227c48e76ffec898f41fd30b7f6c237ae94b28225b9c4112002f0d5fc0764ba65f5836f6159aa2d347f21f7c6b1baae8dabec63b71f40defdd90146e7f859cf71294a7035c656b06a7889aeb6d2a8b58e79f7156e7d951e989beb02778440ab687556373d4b12032944224bafd41e5e60f03ce64aacafd7fdb5503a0d1ff7f5e838c21232096a3bba4daea846e6cdb2fe037cfba9a1f968fcf80ae12aefaa451d1179a5a8a682d346cc7f3fd1c0d113e0e6367da2b035531b8e0ca976e4789f7919d470ff9826a3fac70778805d1ea1dafc12e337582a70979b298958556ba81d05a591bd6255ca2e74855cd0caf8a9ed36938db99351626430463c85916d5592ca59f5921376311125a55b980e8cbdac447da3dd836f911c215a894b176276bb4bef81c8c64c1330f3d83ad9a58a739d296d16142585f0d358af85aca9a9ec633e6e00f0b1d86d2db82811b3a209a34417172a09fe4716da886b0b41c872ff55618b2488a72f6dbd0d3b8be5f927a24f455dea87d4ef37386dbe17847b8068e0f50ad85d4494a847253ccc4db2a1f15c6cc1864c161cc9ad958928d3d9fdf1335b1cf7b3aa7ea7ed8540d8d5b18f11f798011c3267a571df095a0321aaaedcc6d1828c3b07391fdfa326c39518cc739edfde7c2c8de121ea27fbbc87fc197f9302f4137ad05080ec684e6dfcd0d77731fc0a
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151487);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/12");

  script_cve_id("CVE-2020-26062");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv07275");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv95095");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cimc-enum-CyheP3B7");
  script_xref(name:"IAVA", value:"2020-A-0502");

  script_name(english:"Cisco Integrated Management Controller Username Enumeration (cisco-sa-cimc-enum-CyheP3B7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-cimc-enum-CyheP3B7)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Integrated Management Controller is affected by a vulnerability due to
differences in authentication responses sent back from the application as part of an authentication attempt. An
unauthenticated, remote attacker can exploit this, by by sending authentication requests, in order to enumerate valid
usernames.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-enum-CyheP3B7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb11d05d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv07275");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv95095");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv07275, CSCvv95095");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26062");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(203);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:integrated_management_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Unified Computing System (Management Software)');

# 4.0(4h)C and earlier
vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '4.0(4h)D' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv07275, CSCvv95095'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
