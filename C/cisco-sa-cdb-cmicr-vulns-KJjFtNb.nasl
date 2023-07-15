#TRUSTED 9883db9385f8ac0186c65e88a84c4a353de32670b87e9cd3f256237d9b4b6cd3b7fc57b17625c542dd68a9c60edd2f98176833a170f8442b3e7894b1389c0e6dd9127b73b691d8f617638e0e71d183bcffc601a2a5eae7427033f4862c51e71392d2e126aaece9d1ae24bb46c7949c0d8c3fb614ce73332eab10c1313a33da6c210db5d96d657269411d221a7a0bbe3c20822ece7693d52512328a977d629d9eaf38f38fbb53a2ad8da70000a314460d32aad2f72ac1523e0c770f53467378453d8c25c0684475b9962f4eb76047a1cbb556473f2d9da884817946356457a35310995c38f05fd2908a7ea715f5aa48c9a6fb9558f725cd7b61000145af504a43504c8e42026bfa3784dd15359a5e0426407a383720e32a1e90549adbc1e7fe07ab748ab63c6b179b2c2772428ae8107b4142f8a535f77628df41698a567248bda74a13f4a6a1e7474015db007a2f228eda3c112ec53e51a82365078c892f0253eb17354db747d776a303e14bfb3b1c2ad362d8a2fa221b94f71e1b7a176fbc34cd1ab8b20fd0baf3d9f35e78870ca2badd7203515602a90a46490d400932ccbd6e711053fe9c6754f5f893e959e8148b54790357dd36b89fe908ea23c04e7c3944484fb4fff2ab5948d2843ba5143323c62ae7fcf5c5bfe65f1df01be35f6ad110e691a2aafef0ba98fba95b49b7a6a51bb3f44b67e74b3de9002535248620cb
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160085);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2022-20661", "CVE-2022-20731");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz02634");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz30892");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz34674");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz42624");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz57636");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cdb-cmicr-vulns-KJjFtNb");
  script_xref(name:"IAVA", value:"2022-A-0163");

  script_name(english:"Cisco Catalyst Digital Building Series Switches and Cisco Catalyst Micro Switches Vulnerabilities (cisco-sa-cdb-cmicr-vulns-KJjFtNb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Catalyst Digital Building Series Switches and Cisco Catalyst Micro
Switches Vulnerabilities is affected by the following vulnerabilities:

  - A denial of service (DoS) vulnerability exists in the boot loader. An unauthenticated, physical attacker
    can exploit this issue, via the ROM monitor, to cause the device to stop responding. (CVE-2022-20661)

  - A remote code execution vulnerability exists in the boot loader due to improperly enabling Secure Boot. An
    unauthenticated, physical attacker can exploit this to bypass authentication and execute arbitrary code
    with system privileges. (CVE-2022-20731)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cdb-cmicr-vulns-KJjFtNb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09e64044");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz02634");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz30892");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz34674");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz42624");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz57636");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisoc Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20731");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(489, 1221);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var product_info = cisco::get_product_info(name:'Cisco IOS');

if ((report_paranoia >= 2) ||
    (tolower(product_info['model']) !~ 'cdb-8p|cdb-8u|cmicr-4ps|cmicr-4pc'))
  audit(AUDIT_HOST_NOT, "Catalyst model CDB-8P, CDB-8U, CMICR-4PS and CMICR-4PC");

var vuln_ranges = [
  { 'min_ver' : '0',        'fix_ver' : '15.2(7)E5' },
  { 'min_ver' : '15.2(8)E', 'fix_ver' : '15.2(8)E1' }
];

var workarounds = make_list(CISCO_WORKAROUNDS['show_version']);
var workaround_params = make_array('pat', '(CDB|CMICR) Boot Loader.*Version 15\\.2\\(7r\\)E2');

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvz02634, CSCvz30892, CSCvz34674, CSCvz42624, CSCvz57636',
  'cmds'     , make_list('show version')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
