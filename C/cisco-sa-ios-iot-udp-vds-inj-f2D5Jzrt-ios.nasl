#TRUSTED 412ebe655c03c936270faf382c884ef8daa4242b7f6a9fdeca58117a5eea5d6ee47f39e3078935724dcb36df049a468166ca13d7a9b2d900e31ce6fd519f6f15ae5abf184e0e92be7f44f5f2194f5240ca9335c79d7b88441b61c0d0942c68c4e800f8596583f455c8a967b678cf9cc168e37135fc2f3c3447656d5000b9f69223c923f05b582f0b4d95bc573941e45a43f998cdf99b8263b4af8fde414aedbda4fc5c07a983c89c6cf4161a6e937bf4b996a2319035098e64657fa89197464a1559bfa6d16ae380ae462f91959f271f5ac586d331e1478fe7d7cf801e3a5a0654556b60a6d84a1e124d9ab73ab03bef4b707b4e45af4d8a5a865042cb06f5ae535f693309ad579f01be1278aba53ae62e9ec135b6ff259c8b867b579251ae72527f111bbba1a9f2591c5abc85ada1fb82323b4da330a7072dca7665d046bd25872d865fdc2606e3c888119f7b8b5279115b24297e15708d9e880f9795b48796da8eaa6406c9dd0783e5a11997971a268e831b3855876bf32f1d28287603459ba252319384d2efb057cdbfc229aea81a954b71e12d9686b314f7d3d5fc5ecc389016bfb51b21d7cd18be3b48aae54d35577d9280a59cb0a87f87539934f6fb57d2d92a2b7a6a86fb2ab6670c22180a1607a5d77d37b40cc0cf8567fa455d20f952a90492a9582621a9a2edc8ea5464656b6dbc36b89c187c01e66bba4c1ca4d5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137147);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3205");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq66443");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-iot-udp-vds-inj-f2D5Jzrt");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS Software for Cisco Industrial Routers Virtual Device Server Inter-VM Channel Command Injection (cisco-sa-ios-iot-udp-vds-inj-f2D5Jzrt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by a vulnerability in the implementation of the inter-VM
channel due to insufficient validation of signaling packets that are destined to the Virtual Device Server (VDS). An
unauthenticated, adjacent attacker can exploit this, by sending malicious packets to an affected device, in order to
execute arbitrary shell commands on the VDS of an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-iot-udp-vds-inj-f2D5Jzrt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52e14c10");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq66443");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq66443");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3205");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS');

if (('cgr' >!< tolower(product_info.model) || product_info.model !~ "1\d\d\d(^\d|$)") &&
    ('isr' >!< tolower(product_info.model) || product_info.model !~ "8[02]9(^\d|$)"))
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list=make_list(
  '15.9(3)M0a',
  '15.9(3)M',
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
  '15.3(3)JPI',
  '15.3(3)JAA1',
  '15.2(4)JAZ1',
  '15.0(2)SG11a',
  '12.2(60)EZ16'
);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq66443',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
