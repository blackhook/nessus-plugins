#TRUSTED 0c5810418ef5982cac81fce2d776b0248c12d518def5f283831dd9785bf033272f0a57a2a814c3ddbf533fe0e1ad4a08c5ff2a05af6a9e007f7aad81489850f7124803de09aab45995c732ad9e666c21701dbbc4b0b57efbe85328b958fdf2f83cd47a744fd175c012c8495af16663687ac6404bcf0260ef56635cd668ee8dcf09c6781480da3a30bac5d76ffe99650253fef29c0bd67f94a003c26a928041f3f68a388cb98cab06e654644889da1781af0339312d9eec6cd16393b9c630624604a6c32e23c17f748ec198ae711de790dc30dcc98606a9360fd2bf1b5674166ca6e6b4391a145cf87403e7e5354fceb1ee6ea7df3fe720496743fb8c27d33a28921db8983620ccb121322f180118824d8050b4a29b5cf16afcb59ec5fbb5276c043a885146171d7b0a548659bb0d142da396c3c29547b59c284f1c98b35b3afa1ef0e6f586190ba1c2a853c79aeca2ac237403ac00128ada887a6cdad2a6e0d3562f8a0bd88012285bd0889dfb096446191c870773a5c39686b4f7da6411670220c0f2434ebba57982172de05c947dfd135b5d5b661ed1d3e0a52db6da8ca1d0791dbe4f0b3e686a20f7d7efdbf618258467cc7e24d9786ba31374080f0460e8d465914dbdbd61d3d4ee0fcc60a77d8365f6fd418b68a48fc3583720dd59ce2a6ddfcd04db7f03fa2d9342385df43cd472cd70fe03cc2e286194ab8ba4599e2d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139926);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3234");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo56332");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-iot-vds-cred-uPMp9zbY");

  script_name(english:"Cisco IOS Software for Cisco Industrial Routers Virtual Device Server Static Credentials (cisco-sa-ios-iot-vds-cred-uPMp9zbY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a server static credentials vulnerability. The vulnerability
is due to the presence of weak, hard-coded credentials. An attacker could exploit this vulnerability by authenticating
to the targeted device and then connecting to VDS through the device’s virtual console by using the static credentials.
A successful exploit could allow the attacker to access the Linux shell of VDS as the root user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-iot-vds-cred-uPMp9zbY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a014c20");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo56332");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo56332");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3234");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(798);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('audit.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');
model = toupper(product_info.model);

if (model !~ 'ISR8[02]9([^0-9]|$)' &&
    model !~ 'CGR.*[^0-9]1[0-9]{3}([^0-9]|$)'
    )
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list=make_list(
  '15.8(3)M5',
  '15.8(3)M4',
  '15.8(3)M3b',
  '15.8(3)M3a',
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
  '15.6(2)T3',
  '15.6(2)T2',
  '15.6(2)T1',
  '15.6(2)T',
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
  '15.5(3)M',
  '15.5(2)T4',
  '15.5(2)T3',
  '15.5(2)T2',
  '15.5(2)T1',
  '15.5(2)T',
  '15.5(1)T4',
  '15.5(1)T3',
  '15.5(1)T2',
  '15.5(1)T',
  '15.4(3)M9',
  '15.4(3)M8',
  '15.4(3)M7',
  '15.4(3)M6a',
  '15.4(3)M6',
  '15.4(3)M5',
  '15.4(3)M4',
  '15.4(3)M3',
  '15.4(3)M2',
  '15.4(3)M10',
  '15.4(3)M1',
  '15.4(3)M',
  '15.4(2)CG',
  '15.4(1)CG',
  '15.3(3)JPJ',
  '15.3(3)JAA1',
  '15.0(2)SG11a',
  '12.2(60)EZ16'
);

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvo56332',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  router_only:TRUE
);
