#TRUSTED b2865601571ca974269a981e181653fe715f89aa015d938e524260ddffc6a2915641d096c4d306a12003519d7b9c66a9447bccc42223914c0845a89f47f55e0d57026d3dae569ee16fc3ee73e7c2b379f90d9ced7d178b39c028b90d2aa2fbddd93287ee6d7990530965f615350b2659fd05931def1f1eb8fa750a64737a6b841ede171c7321f89006a5fd8a8a1f43ff6c2acfda7997ae1d6bd5b93f483c650cf3e1bc7210a1d39c88e19607124992884c8c31b437d99ab78ac9cab481f6afe5524412df7d710969bac908d14d428f2b37629fc83c780b9c1cb8e9d2e4bcba6669513ee75f10038ffb825c590dd30dacbc5212cd42a4b7eb931941d374a442ae9a1000e07c0e2c87cce76fa53120d806d49f8bcb930f27d0e3bcb7d83614cc8ddefce24db9f01b7d305abe2e81600f6c0cab7d8204b93eb4b5741faab434f180fb69c697b8bec134be8297749d47937ef8148e53eb1487e627e438cb1aef389de11c6955c9dcca12424e5337105c63cfae0e6dff887e3b07f16b798aa34706e2621e90127c6e5bef8c0020db0955a83613625b19a73c17b97f0914adf0d12727a5e1e7b45e5693e154c82b719b3e78c33ca85afd3c957a8e57f2cb6bb3d42b5feb5c9cf88aeff1838499e26b57f75a144c3440a8186f581d158f2bf458ab03c98d5ed31a8d01c1124170dc4fe331a8af0515820c664f39ca45fa7c1117ef7b3a
#TRUST-RSA-SHA256 2bbf6c0efa805f6e38601c73dce913f4b4775720dc06b5440e3763cafad4a7a86c94d315aed2a4a5381ef960ec94fc3d09ee3848764225387b6cc52fb51374ca1cd6ee844b92aa0de8bf408798989c1218aa07e4e4b05f315945a1de93407d342254ba641654b1cf290d2d32511b665c718673167ea3af6b25ee50d2fa00415567a197edb523c63ea000c5da2756da3797117184365b611c2c515d6f95b026a38b29d399745055459400547d2e0f7172d415b5d371da95d2c43de51466098b0a79c122c6655cf1a5dd9d145072a8039f6fef7c1d3de51c48a2221c604691d130f7972f9028cae87685097681b647c7a7f48df308bfe9795187a3ae6402ac54265a903e39f19bf6f29a5c811ef98c7674f1eb16d8fa2c8309c9048a5b74c4d93667544591b54d6133a6dd7835c20e4c8fb4c6f34f9aa691af1ce1c3a7eb54b4e4eda1598fdc354c0d4b7ea94297fd26595d383d67588ab9b8244cdd37a9a0654f7a2129ae3f973d9584461b227babddb24e0104d89f972b3f223b1c7b956f5e744da28460b152352d5967c8f1f0a20692f86306bcd9c1b24c32474cd32a9bc341dc4c4ade3d8b521d7a8e25dcdd5c2984c4cc94aadf4d492367f930a85358584302df215970254e1932d6351c3a635691f293a9740abd63a7c4b4f9dfb95a2e1f70e671f78a4405cb8955b861c33de1884ee1d9580858b85bba368ccbc54637b9
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149301);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2021-1501");
  script_xref(name:"IAVA", value:"2021-A-0205-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw26544");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ftd-sipdos-GGwmMerC");

  script_name(english:"Cisco Adaptive Security Appliance Software and Cisco Firepower Threat Defense Software SIP DoS (cisco-sa-asa-ftd-sipdos-GGwmMerC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a denial of service (DoS) vulnerability due
to a bug which causes a crash. An unauthenticated, remote attacker can exploit this, by sending crafted SIP traffic, in
order to cause a DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ftd-sipdos-GGwmMerC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79f85bf3");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74594");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw26544");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw26544");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1501");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(613);

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
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.8', 'fix_ver': '9.8.4.34'},
  {'min_ver': '9.9', 'fix_ver': '9.9.2.85'},
  {'min_ver': '9.10', 'fix_ver': '9.12.4.18'},
  {'min_ver': '9.13', 'fix_ver': '9.13.1.21'},
  {'min_ver': '9.14', 'fix_ver': '9.14.2.13'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.15'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['sip_inspection'];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw26544',
  'cmds'     , make_list('show service-policy')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
