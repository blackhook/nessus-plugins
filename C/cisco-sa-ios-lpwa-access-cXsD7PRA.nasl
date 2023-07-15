#TRUSTED aa05ff48067b61bec325ebadf0201f5e12c85cd186d9e8796101cfaf6cadd6ba557526122360932e3d755e963e31e11cf78bf7c363a8bd9d0899b804a18c1f4e5c26662adf73b889ad26a525e8339b513bf3eef7bdfcf82f551c426a34859e382e026eba0bd6b3aa47586c887a50140608addef1abc9517dda03561668de84eb147ef00ec787e8c53a249ebbdc6b86ee9424d3aa9415067794618efc01ad798080fd2c6ff70510b9d28670f6f35ed20b5c639c6e4a5799b27236cdcedaf718a63d9056e6c6f0de205fa48ce19a460ca3cb3c4ce882aef2956695dab7021789608f5d144b753d92becaf0c24f14eaf033b684c83d8fb773ce340841a974dde04f598004e18a570ec88a7cebb867b1d1fe323f312182204880a7779c102a7a8a63c3f24e38906bca40dbcea677442907fd8c464dc03642ec0a7f8a54437e9dbe70d76620ec25479ecca0052be57ddd095a1a2f9504897551f3fe04a794521d76656661277538ecebd58356bec988cf09cb6e13b04c0921791cf9c8787d5399addbab9ad8ed790087082aefa59980f5d6dcfacf24a220fd0b525deb772ceac81b7c96ac97786bc68600fed3b7724fddc822219c76cd06a976da496057b840bc2935030e4e1fa9d8baab8f39a6a68a6f30420380486764f4b8adf26b4e1cbb2c78bacaa0d41bee0251e8bf7c58582ca74d8b2d5431cfdf73149a57564350c7891781
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148296);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2020-3426");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr53526");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-lpwa-access-cXsD7PRA");

  script_name(english:"Cisco IOS Software for Industrial Routers Virtual LPWA Unauthorized Access (cisco-sa-ios-lpwa-access-cXsD7PRA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a vulnerability. The vulnerability is due to a lack of 
input validation checking mechanisms for virtual-LPWA (VLPWA) protocol modem messages. An unauthenticated remote 
attacker could exploit this vulnerability by supplying crafted packets to an affected device, to gain unauthorized 
read access to sensitive data or cause the VLPWA interface of the affected device to shut down, resulting in a denial 
of service condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-lpwa-access-cXsD7PRA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?041adee3");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr53526");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr53526");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3426");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS');

var model = toupper(product_info.model);
    
# Vulnerable model list 807 Industrial ISRs, 809 Industrial ISRs,829 Industrial ISRs, CGR1000 Routers
if (model !~ "^IS?R807([^0-9]|$)" &&
    model !~ "^IS?R809([^0-9]|$)" &&
    model !~ "^IS?R829([^0-9]|$)" &&
    ('CGR' >!< model || model !~ "1\d\d\d(^\d|$)"))
    audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list=make_list(
  '15.2(6)E4',
  '15.3(3)JK99',
  '15.3(3)JPJ',
  '15.6(3)M1',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)M6',
  '15.6(3)M6a',
  '15.6(3)M6b',
  '15.6(3)M7',
  '15.6(3)M8',
  '15.7(3)M',
  '15.7(3)M1',
  '15.7(3)M2',
  '15.7(3)M3',
  '15.7(3)M4',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.7(3)M5',
  '15.7(3)M6',
  '15.8(3)M',
  '15.8(3)M0a',
  '15.8(3)M1',
  '15.8(3)M2',
  '15.8(3)M2a',
  '15.8(3)M3',
  '15.8(3)M3a',
  '15.8(3)M3b',
  '15.8(3)M4',
  '15.9(3)M',
  '15.9(3)M0a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['show_control-plane'];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'cmds'     , make_list('show control-plane host open-ports'),
  'bug_id'   , 'CSCvr53526'
);

cisco::check_and_report(
  product_info : product_info,
  workarounds  : workarounds,
  workaround_params:workaround_params,
  reporting    : reporting,
  vuln_versions: version_list
);