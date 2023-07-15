#TRUSTED 65c096c7efc80b54f79528a40c8a548a5d11dfb7e163f2e21a31143cc806db98f93dd0d0fef3fb86827c4532cb90447e283140f38a07666f4cabfc9bdac1bd8be0c680a20b4f02aa896e4af631db0365ff854968c2870cdf3d604cea5ed28b36d60767ea87be659e2b1f0a45f11153861281064d129fd6298541ecac3fd152ac1188a74ecac45d0c901d303236d225f43307c323000a6a5e5ca870a9d8d72b0178fe8f832a21b6b52744bf016d9640e2c4cc967302423c514bd0bc330a8edeea097ef5aacbade108a7e3f44e59dc531b2e0b6b137cbed1989ced81507acbcec73f10d6dc97554ed10858dc21601fab2afc6547c8704b0c8b3fac625935ea5bf06d31ade742db7a566b42bc613c41ff2ed9bbaf2f508589e5b26341778191706af43ef8df4dcf03428769671d2082312d8a3269798ae6d077b4465f366b7f7c5dc9fa013e48835ca18d669d70fda0be31458998dd5c035f70cde0d19257689d290e4eae7402cc9d4b771a0b21a28506f81fcfda2967e31b3cf77f503311e36ce9d35c56a52601023a2a00e85a5510930c2848c4aa49746a7d10faba113466920c61215899fc555712dc4c234ba1d2375092c22fcfe319802667b3c3e2fe48a149cfc64c073d1d353dd4d71885f98de10beeb8d7a5bc26d6fe9eebbeae572b91c3f967c5dec7bca75411b0e36b61927d51f8c27a07317bf61975bfcc4200df18aa
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140218);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/10");

  script_cve_id("CVE-2020-3545");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd72523");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fxos-buffer-cSdmfWUt");
  script_xref(name:"IAVA", value:"2020-A-0403");

  script_name(english:"Cisco FXOS Software Buffer Overflow (cisco-sa-fxos-buffer-cSdmfWUt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Extensible Operating System (FXOS) is affected by a software
buffer overflow vulnerability due to incorrect bounds checking that are parsed from a specific file. An authenticated,
local attacker with with valid administrative credentials can exploit this, by supplying a crafted file, to cause a
stack-based buffer overflow that can be used to execute arbitrary code on the underlying operating system with root
privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxos-buffer-cSdmfWUt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?addee757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd72523");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvd72523");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3545");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(product_info['model'] !~ "^(41|93)[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0',  'fix_ver': '2.3.1.58' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd72523',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);



