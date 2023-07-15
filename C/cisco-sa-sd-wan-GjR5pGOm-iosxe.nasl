#TRUSTED abf89668d5e8e7da44901be868c7c3dcbfedeecd5b46d64c957761f6248acd3c645a3729f3fa3785287984f4fd1d3661fb8a166cd3b99fd6136304a0b3f6da60adc80a27a526f7adcee221272894409a570dc5a2ecb45c95bbf4f1e27663080bb21a0db32818f15aebd0237f8442b78efbcf8512616cbd773a2080b0bfd1cb5dac705d24b41638b4183021f26a9816028349f86e874ca73b3a8090fbd57119d41e98f7f7b87f90300f6f7dcfbe9066b0bc3785d94e51da3fa2e02434ba3b1e43c8626187a881e8c5ff532289e4c938ec216d8976da9131ac5d6d06114fe95a31c513316c3efc7dbe55ac64b5dcb37749bb366af301769d0aae303dbf20d2bdc4ff7f00dcbc91cce2454af8d59bdda172dba40407e27ef65d437701281a8922f167dd5c476503f7a5b41209420652808ee6a1318f9a3d19fa0687d8050c05eeef0327e946737e88ec8e624d94f2151734e43ead5027322660fe2eb663a8737482419dad1aa57511a6c19c095c208794e203e0bc92ce059c78bafda69678d030a26c3738cd87ffa2b72dcdfa5cadff160b3368fe6b9d84575d8aa501e942c9b7627f20ba7aab799e5a56535a3976b2372cb4b4c83ca3358f54a59bd2bba69eaf768c6ff8c5d46a4119fea0fa08c56755387af8f7f93872504bbbc1eff2082c847938830e14784b89138baa66c35280c108187bcc5b32d2d7282ff7056bb00cf923
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153562);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/09");

  script_cve_id("CVE-2021-1612");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt63238");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-GjR5pGOm");
  script_xref(name:"IAVA", value:"2021-A-0441");

  script_name(english:"Cisco IOS XE Software SD WAN Arbitrary File Overwrite (cisco-sa-sd-wan-GjR5pGOm)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Cisco IOS XE SD-WAN Software CLI could allow an authenticated, local attacker to
    overwrite arbitrary files on the local system. This vulnerability is due to improper access controls on
    files within the local file system. An attacker could exploit this vulnerability by placing a symbolic
    link in a specific location on the local file system. A successful exploit could allow the attacker to
    overwrite arbitrary files on an affected device. (CVE-2021-1612)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-GjR5pGOm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea29dee5");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt63238");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt63238");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(61);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

var version_list=make_list(
  '16.9.1',
  '16.9.2',
  '16.9.3',
  '16.9.4',
  '16.10.1',
  '16.10.2',
  '16.10.3',
  '16.10.3a',
  '16.10.3b',
  '16.10.4',
  '16.10.5',
  '16.10.6',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1d',
  '16.11.1f',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '16.12.1b',
  '16.12.1b1',
  '16.12.1c',
  '16.12.1d',
  '16.12.1e',
  '16.12.2r',
  '16.12.3',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '17.2.2a'
);

var sdwan = get_kb_item('Host/Cisco/SDWAN/Version');
var model_check = product_info['model'];

#Model checking for IOS XE SDWAN model only
if(model_check  !~ "^[aci]sr[14][0-9]{3}v?")
  audit(AUDIT_HOST_NOT, 'affected');

if(sdwan !~ "([0-9]\.)+")
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvt63238',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
