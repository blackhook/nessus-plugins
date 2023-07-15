#TRUSTED 3566b4cf92646ca986851cf45fd2034ec83cdecb4780c4fe6a5f751416b509fb4f9699358c306a558538eb3cc08195aca0970365939302410c41463cf4d2b9a923926a5e816b775e73af42c4dd280aaca91785ab4d31025edc3c012714382f7c0ebe48ccad6c72d6088123ec1b73242423db21ccddd241bfa13e643fd89567c883976faed73ed061a014b51997b824bca03a7b2a37d237f6a07a4cbf922c5299f9745b03334544fe9c5f411f3c729b131a1c2d1c9fc115c16c6c72b9fac51585c6b8d543958d596aee7d3c381e590654aca1b16b0c5b95203216916e183dadc99792653dfc4123c7404b2f1595da2b666c47d1276fb4fd8405dddde683402200f08d67baf6e0cf2448dd64f6f6a5afc6e1a0409d9750dad1979617f83edb0e7bd90c82e87143e2f92c05eb9a7db8f746c1a3726b8da224da0693a16b1081767ec73757db2080d13d3597512b42ec0b944a19dcc97fa9f521807436fdd052f8f3aa703f76d0260728f83d542fb4bf928267bbe92ddb40cb7b8cc9ac2899ceb9bc06f0802c2f08c88e8f87298f01c689efc5d516a5b9257bb77dc59fa86cb45e74bdf1d980b9def8dd84b7cd073ce71ccf32a07a482c18cd1458dc82e6c2a29ef2c9c55f1c04381ec7918fa92df22335b345bc4061f167ab16479a5b29a30336555737f0cc44199613b50f3d52ce18075c78a61fa70f92dae89c48ebbd1f0f3b0e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138147);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3208");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq27907");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-ir800-img-verif-wHhLYHjK");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS Software for Cisco 800 Series Industrial Integrated Services Routers Image Verification Bypass (cisco-sa-ios-ir800-img-verif-wHhLYHjK)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a vulnerability. The vulnerability is due to insufficient
access restrictions on the area of code that manages the image verification feature. A successful exploit could allow
the attacker to boot a malicious Cisco IOS Software image on the targeted device. To exploit this vulnerability, the
attacker must have valid user credentials at privilege level 15.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-ir800-img-verif-wHhLYHjK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6f3f2c7");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq27907");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq27907");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3208");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

# This vulnerability affects Cisco 809 and 829 Industrial ISRs
if (product_info['model'] !~ "^ISR8(09|29)")
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '15.8(3)M5',
  '15.8(3)M4',
  '15.8(3)M3',
  '15.8(3)M2a',
  '15.8(3)M2',
  '15.8(3)M1',
  '15.8(3)M0a',
  '15.8(3)M',
  '15.7(3)M7',
  '15.7(3)M6',
  '15.7(3)M5',
  '15.7(3)M4b',
  '15.7(3)M4a',
  '15.7(3)M4',
  '15.7(3)M3',
  '15.7(3)M2',
  '15.7(3)M1',
  '15.7(3)M',
  '15.6(3)M9',
  '15.6(3)M8',
  '15.6(3)M7',
  '15.6(3)M6b',
  '15.6(3)M6a',
  '15.6(3)M6',
  '15.6(3)M5',
  '15.6(3)M4',
  '15.6(3)M3a',
  '15.6(3)M3',
  '15.6(3)M2',
  '15.6(3)M1b',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M',
  '15.6(1)T3',
  '15.6(1)T2',
  '15.6(1)T1',
  '15.6(1)T0a',
  '15.6(1)T',
  '15.5(3)M9',
  '15.5(3)M8',
  '15.5(3)M7',
  '15.5(3)M6a',
  '15.5(3)M6',
  '15.5(3)M5',
  '15.5(3)M4a',
  '15.5(3)M4',
  '15.5(3)M3',
  '15.5(3)M2a',
  '15.5(3)M2',
  '15.5(3)M11',
  '15.5(3)M10',
  '15.5(3)M1',
  '15.5(3)M0a',
  '15.3(3)JPJ',
  '15.3(3)JAA1',
  '15.0(2)SG11a',
  '12.2(60)EZ16'
);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq27907',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);