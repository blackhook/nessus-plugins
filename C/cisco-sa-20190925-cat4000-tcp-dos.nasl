#TRUSTED 43dadc06ff6619fa0724081b5f98ec8f8f4d9e69d33ee9d271640be31ebb036b20054edb7eccc54294e70a41cf138dc891a07d180d173fe0da64715b222681a5181c43ca8dd99c6390b2dee8c32e118516e4c470e693703b6ca92eaedbe36e0cc591d84ba037c39a6bc70df2aec0bac3779476099658596a00e703b8845c8a6566a1cf1f33d73802b269b1ddb73e8bbfc7f270092f792f2d27ce22a6b5a9004ed993748cd478f57c3e7f7c3d27956c1a973cd14f6bf5df83b056a900d9292395f47a3038e15899d84137c5f067f255f44759c786d5caee58618d0c1f26ce0db9ce8378d48b70b9a099a8cee45cda2882eb638c02d7656249cf80dcc580ffa6979b8cfd6b26d87711b84d72a4bb4f9e87a78750c1ac6b14f036935de1fb4c555ac0efa65feb6d10ba49744a774bf9787dbca754dc31d2f873cd661ea57f39f7d0c94632904abb13f051d7d88813599c5bf32c20096237d0616b4ca39e312898f7f518fac44cb9b8b56d2f75cd2bef30e36efb29a051f4c24b2499fdd9d0e87d866376d3a5c8d8c393223c13f874de363d8e89c2bb9658f523819d3fbc522df3b4a4d1e6790bdc161f8032a058efc86cfb535ec8412880b4de2d298d28e88a0926952b4b68e73ba04f997ce166b8be16219e9fe367db3ad579f23575caa9e57d2fb69518169cd5b457f9fa8bee068a0cfde58331809c8cb9ac3c09020358437aea
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129558);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2019-12652");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk66730");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-cat4000-tcp-dos");
  script_xref(name:"IAVA", value:"2019-A-0354-S");

  script_name(english:"Cisco Catalyst 4000 Series Switches TCP Denial of Service Vulnerability (cisco-sa-20190925-cat4000-tcp-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is affected by following vulnerability:

  - A vulnerability in the ingress packet processing function of Cisco IOS Software for Cisco Catalyst 4000 Series
    Switches could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an
    affected device. The vulnerability is due to improper resource allocation when processing TCP packets directed
    to the device on specific Cisco Catalyst 4000 Series Switches. An attacker could exploit this vulnerability by
    sending crafted TCP streams to an affected device. A successful exploit could cause the affected device to run
    out of buffer resources, impairing operations of control plane and management plane protocols, resulting in a
    DoS condition. (CVE-2019-12652)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-cat4000-tcp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f0feb22");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk66730");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk66730");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12652");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

# Check if Catalyst
if ('catalyst' >!< tolower(product_info.model) && product_info.model !~ "C[0-9]{4}")
  audit(AUDIT_HOST_NOT, "affected");

# Check model number
if (product_info.model !~ "4\d\d\d($|[^\d])")
  audit(AUDIT_HOST_NOT, "affected");

version_list = make_list(
  '15.2(4)E8',
  '15.2(4)E7',
  '15.2(4)E6',
  '15.2(4)E5a',
  '15.2(4)E5',
  '15.2(4)E4',
  '15.2(4)E3',
  '15.2(4)E2',
  '15.2(4)E1',
  '15.2(4)E',
  '15.2(3)E5',
  '15.2(3)E4',
  '15.2(3)E3',
  '15.2(3)E2',
  '15.2(3)E1',
  '15.2(3)E',
  '15.2(2b)E',
  '15.2(2)E9a',
  '15.2(2)E9',
  '15.2(2)E8',
  '15.2(2)E7b',
  '15.2(2)E7',
  '15.2(2)E6',
  '15.2(2)E5b',
  '15.2(2)E5a',
  '15.2(2)E5',
  '15.2(2)E4',
  '15.2(2)E3',
  '15.2(2)E2',
  '15.2(2)E10',
  '15.2(2)E1',
  '15.2(2)E',
  '15.2(1)E3',
  '15.2(1)E1',
  '15.2(1)E',
  '15.1(2)SG8',
  '15.1(2)SG7',
  '15.1(2)SG6',
  '15.1(2)SG5',
  '15.1(2)SG4',
  '15.1(2)SG3',
  '15.1(2)SG2',
  '15.1(2)SG1',
  '15.1(2)SG',
  '15.1(1)SG2',
  '15.1(1)SG1',
  '15.1(1)SG',
  '15.0(2)XO',
  '15.0(2)SG9',
  '15.0(2)SG8',
  '15.0(2)SG7',
  '15.0(2)SG6',
  '15.0(2)SG5',
  '15.0(2)SG4',
  '15.0(2)SG3',
  '15.0(2)SG2',
  '15.0(2)SG11a',
  '15.0(2)SG11',
  '15.0(2)SG10',
  '15.0(2)SG1',
  '15.0(2)SG',
  '15.0(2)EX8',
  '15.0(2)EX2',
  '15.0(1)XO1',
  '15.0(1)XO'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk66730'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
