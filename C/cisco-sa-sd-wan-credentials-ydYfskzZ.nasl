#TRUSTED 630c4de14d2da79c1ddad77f9b582398d334a367ca10cf7377eca6bff5cda577255a127c33e4c36b0a532bae64211f26a75ec9061d80f4199349715e0ea389e6c5f77483565e5dc688229401a90760c59cb206e6b483079f3cc7ee265ac998deb0a311b8ac76aee3496883a25f9622100ed26c4e5b341c12f28ef4353cc8fc0576738f82477a01737cd8c7c11f1e094e2704e55b4aaf3b63e87d201a5f87d63a14298fc537e72251b260fc79ab2f7184ea7e5376c0f212d9bf80b84665dffa9111b878add9c42c117eaf3d9dcc1e8cac2d98504729aacfd588d2f0a25ad945ab1fe0452f2412631e6fdb2f1114b5d52e093432e778cb31d439f42ea51735c44d8525cd273fd90d02e978d050e052b19321223e0e986a771cb9fd919064aac64a8ceb075aa650916d34d57bfc7593fc59a6445805cb2774cb783aeadac65f3db0c30eb22c69f69f76ef6e45de51d29514c7dd0eb709487e0e957bb79cb48c84a27259f4f203be0ecf93dd3788af77d25a43dab7fad39a68e1db0f6ed0fbca036fc9703c73c4060fa2e15711205f094610b57686d767e9c41b14e5b53a3d3920abc16e168925c22af341c6aebb2eaae710c68225e74a2ac732216a6c898c3c185590e9c15e4aaa487c2ff4f5b4e2190cc9457c0c761d343a3b41d8d0e9749df700b049717091a97cb1341143b665a6496157c00a89e062d57a3c959b879d608bbb
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153549);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/01");

  script_cve_id("CVE-2021-1589");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy23058");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-credentials-ydYfskzZ");
  script_xref(name:"IAVA", value:"2021-A-0435");

  script_name(english:"Cisco SD-WAN vManage Software Disaster Recovery Feature Password Exposure (cisco-sa-sd-wan-credentials-ydYfskzZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the disaster recovery feature of Cisco SD-WAN vManage Software could allow an
    authenticated, remote attacker to gain unauthorized access to user credentials. This vulnerability exists
    because access to API endpoints is not properly restricted. An attacker could exploit this vulnerability
    by sending a request to an API endpoint. A successful exploit could allow the attacker to gain
    unauthorized access to administrative credentials that could be used in further attacks. (CVE-2021-1589)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-credentials-ydYfskzZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a48700db");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy23058");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy23058");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1589");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(256);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.4' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.2' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.2' },
  { 'min_ver' : '20.6', 'fix_ver' : '20.6.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvy23058',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
