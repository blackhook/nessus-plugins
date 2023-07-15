#TRUSTED 452fcb0c1372c66e25b37216a6675773a42b025cc2764f8d26d7175b72cdedc1277dc555f104000e8bcf40330148e79a3eb9d12546c7f1322d3ff70ae50522cab7f1f212e7a3765e76c19a3e6744da50749fd919d9f5fe51e8dae6ef92cdb2a83375444533c425fe6144241e6f99b84ef8b3448f3f0e73e8f0660dc2145ffd41de8aee5b7041c0c21373cf9cd57ed6eb1e2d985ec2322aa41b34bc4ec5576bd2d052e5e138293003adb2df3ff6678b0c04a4b502ca98d94f4808c72b0b7cdc17077d5cc61504b7fa8390f8db8d26e6fe976954c8251bfe48d5d36d445d46729cda5d0d5bd1a68331b1b99550f41b0cf9ab96e2cbfc4c1b6e4e2839c5c7abae3e30ad16e0e104e3e5559a1543762e9209c648aaae8cdf64366a3cfaf37d53d3bd85c76c5c174edb4355655371daf3e58c6091607405a7b7a8731b568b52f7f8d1594b72545098ab0d2bfdefa5d64d88f35309787fa78f08395465dc348545d08fc3d3a9a2bebc93b241f5d6280db47e70a3b88b54794c114c09e59c98f8d733df179c1d993dce32127d7f2086de6e6a73e99d4bb7f1a040d7c6c2477bfa06d82b747dcbf62a0f518d3329b8f1b166b64d7fcd166e318b273fb55c533240094e012a0f5dee3180ac623e96eae40c3c513c28434f160ea8895c1c98ec23b264986aad817fa4e2c925bcd83e8ece66ac3e1f3932ca69d782efd6fc9b4e79a8fcfdb6
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149363);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/17");

  script_cve_id(
    "CVE-2021-1275",
    "CVE-2021-1468",
    "CVE-2021-1505",
    "CVE-2021-1506",
    "CVE-2021-1508"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28360");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28390");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28402");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28454");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-vmanage-4TbynnhZ");

  script_name(english:"Cisco SD-WAN vManage Software Vulnerabilities (cisco-sa-sd-wan-vmanage-4TbynnhZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by multiple vulnerabilities that
allow an unauthenticated, remote attacker to execute arbitrary code or gain access to sensitive information, or allow an
authenticated, local attacker to gain escalated privileges or gain unauthorized access to the application. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-vmanage-4TbynnhZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?769d3f6f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28360");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28390");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28402");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28454");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu28360, CSCvu28390, CSCvu28402, CSCvu28454");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1468");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 862, 863);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.3.3' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu28360, CSCvu28390, CSCvu28402, CSCvu28454',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
