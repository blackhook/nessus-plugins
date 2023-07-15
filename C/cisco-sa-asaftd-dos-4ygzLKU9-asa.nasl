#TRUSTED 8eccd508f2558e761e54dabdf4d4caf0e08d268e1a4f5d49f8ae205c427f369164be932b3fd90e0e8d8920df362e18ed13922091f7cbf8384ddda80ff77f357f7a897145ac0d8d20a4832a07be1e7ae56f1343337e80017d4f3bf7906846a2ae5426562c9f8514732cbabc26089a28dd4ab08d6f6d1a9016c53f96ebb1800bf2eaa212c06f4b60c3fcb82521f2514b29acc629416faeec8aec12e836b720d96b1fae24db702f5f4593400f6dd26ac9480abc4e7dd6d4db6ea2b5cb1179e160c7b75f7a26161a16e3fff9998b1db8364c7464d9712e87c2a57ba01022539595b60ea5ca02c4e9504838d4125b5fb3804d0b3a618d350daab5632704a81d7ddf301fd3d2e5ab5a3575b1bf9c4162f799cb0f15b4eaecb460b3a65c3577380dc37c745b3d448fb531b2cfce10835398d340f5434fe08c21211c7bd9a9bd89fdc70733f44302517425ec53bb31fcc26a02eeb10acaa5a3de5c92b8a6f9afff07726426ef97df5ca0edfc121a49c1439bd9efe71af4e1bea12367ab005be7444e3a4e077583483952c942fd45a21e71b8232dfab2502c14754d9d280374d3cccca431228cd1c6feafa58afb7064765df459fa69df662265d9de344bbf55d0ebb710821fca468e598b493a85b2c3334de6634c9102f503a76d0f2a2e534c9606963fe80d34ea4703aba565de98d2f3841e2bd29dfd08b2675f56d476319ae55d24823e
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155445);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/07");

  script_cve_id("CVE-2021-40117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy43187");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-dos-4ygzLKU9");
  script_xref(name:"IAVA", value:"2021-A-0508-S");

  script_name(english:"Cisco Adaptive Security Appliance Software SSL/TLS DoS (cisco-sa-asaftd-dos-4ygzLKU9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability.

  - A vulnerability in SSL/TLS message handler for Cisco Adaptive Security Appliance (ASA) Software and Cisco
    Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause a denial
    of service (DoS) condition on an affected device. This vulnerability exists because incoming SSL/TLS
    packets are not properly processed. An attacker could exploit this vulnerability by sending a crafted
    SSL/TLS packet to an affected device. A successful exploit could allow the attacker to cause the affected
    device to reload, resulting in a DoS condition. (CVE-2021-40117)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dos-4ygzLKU9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29eccd9b");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74773");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy43187");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy43187");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40117");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.8.4.40'},
  {'min_ver': '9.9', 'fix_ver': '9.12.4.26'},
  {'min_ver': '9.13', 'fix_ver': '9.14.3.9'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.17'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [WORKAROUND_CONFIG['ssl_vpn'], WORKAROUND_CONFIG['anyconnect_client_services']];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy43187',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
  