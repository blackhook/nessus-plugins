#TRUSTED 4986776b3e05e15056840c05a91e72f3c6a6832ff41e0d8beaacd9ba5d8be33aa903828ef55a17e5aa632a1f638a556fe753fa7c7679a548b3cf945e3f24f9a00fac1a82e41b819a2a13d2f6883d23774356f12b9c39b3d5e8399594935e5322ec18efc1a495c30fc7a8b3c04140f0708b1995161e9e8492c2eef5faa3c69f03b9b7ed6f910d45ec8d39dbf95194bbe9a1751be7f140155604ebf811f4df11d1d030871968b240412008d9d52f10ed095cfb769eab8c15e1f6aa56104319e35200c3022979387fa21fa6d7df43fbb2a931b048dc61156ea1a9e00340c7ddc6b71426bbebfc148bd58cb328308ef1fd575a5952efb5ff85a605d9d3ff4274e6976f07978d6420b51de5b5145a74f7090ad7010ee0c518a7f032db13eec3872687fe5341bcaa74b732d3bd467e6f4091bf2b40ead3219f54386a4f3c0151a33fc02e6c5b6300841729ed146960d9554ad4e6015a2244e6267e2dd944cc85032440d2ebe5c5bd8e2e3dfcabdfca58385689da5c346a49016e9ec3ece4dce2a83587dbfae2c47d66e23af1afa90c71847de0723ad211cefe2f4e6c6dbb810aad2f9888909640714fcc1b18e373652da74d7fff32c5c56ced911982d33a7edadffc68e9ecd841d02684efa4569a4012c9cbb95adc2b1851ba07f378fd960f92532d4f7257a1caf1fb9efb6fc79f1cc95184733b2a03ddfbc11ae622df8af69b2e8a84
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130092);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2019-1737");
  script_bugtraq_id(107604);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf37838");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-ipsla-dos");

  script_name(english:"Cisco IOS Software IP Service Level Agreement Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is affected by a vulnerability
in the processing of IP Service Level Agreement (SLA) packets by Cisco IOS Software and Cisco
IOS software, which could allow an unauthenticated, remote attacker to cause an interface
wedge and an eventual denial of service (DoS) condition on the affected device. The vulnerability
is due to improper socket resources handling in the IP SLA responder application code. An attacker
could exploit this vulnerability by sending crafted IP SLA packets to an affected device. An exploit
could allow the attacker to cause an interface to become wedged, resulting in an eventual denial of
service (DoS) condition on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-ipsla-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74b82563");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf37838");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvf37838");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1737");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
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

version_list=make_list(
  '12.2(58)EX',
  '12.2(58)EZ',
  '12.2(60)EZ',
  '12.2(60)EZ1',
  '12.2(60)EZ2',
  '12.2(60)EZ3',
  '12.2(60)EZ4',
  '12.2(60)EZ5',
  '12.2(60)EZ6',
  '12.2(60)EZ7',
  '12.2(60)EZ8',
  '12.2(60)EZ9',
  '12.2(60)EZ10',
  '12.2(60)EZ11',
  '12.2(60)EZ12',
  '12.2(60)EZ13',
  '15.2(2)S',
  '15.2(4)S',
  '15.2(2)S1',
  '15.2(2)S2',
  '15.2(2)S0a',
  '15.2(2)S0c',
  '15.2(2)S0d',
  '15.2(4)S1',
  '15.2(4)S4',
  '15.2(4)S6',
  '15.2(4)S2',
  '15.2(4)S5',
  '15.2(4)S3',
  '15.2(4)S0c',
  '15.2(4)S1c',
  '15.2(4)S3a',
  '15.2(4)S4a',
  '15.2(4)S7',
  '15.2(4)S8',
  '15.3(1)T',
  '15.3(2)T',
  '15.3(1)T1',
  '15.3(1)T2',
  '15.3(1)T3',
  '15.3(1)T4',
  '15.3(2)T1',
  '15.3(2)T2',
  '15.3(2)T3',
  '15.3(2)T4',
  '15.0(2)EY',
  '15.0(2)EY1',
  '15.0(2)EY2',
  '15.0(2)EY3',
  '15.0(2)SE',
  '15.0(2)SE1',
  '15.0(2)SE2',
  '15.0(2)SE3',
  '15.0(2)SE4',
  '15.0(2)SE5',
  '15.0(2)SE6',
  '15.0(2)SE7',
  '15.0(2)SE8',
  '15.0(2)SE9',
  '15.0(2a)SE9',
  '15.0(2)SE10',
  '15.0(2)SE11',
  '15.0(2)SE10a',
  '15.1(2)SG',
  '15.1(2)SG1',
  '15.1(2)SG2',
  '15.1(2)SG3',
  '15.1(2)SG4',
  '15.1(2)SG5',
  '15.1(2)SG6',
  '15.1(2)SG7',
  '15.1(2)SG8',
  '15.2(4)M',
  '15.2(4)M1',
  '15.2(4)M2',
  '15.2(4)M4',
  '15.2(4)M3',
  '15.2(4)M5',
  '15.2(4)M8',
  '15.2(4)M10',
  '15.2(4)M7',
  '15.2(4)M6',
  '15.2(4)M9',
  '15.2(4)M6b',
  '15.2(4)M6a',
  '15.2(4)M11',
  '15.0(1)EX',
  '15.0(2)EX',
  '15.0(2)EX1',
  '15.0(2)EX2',
  '15.0(2)EX3',
  '15.0(2)EX4',
  '15.0(2)EX5',
  '15.0(2)EX6',
  '15.0(2)EX7',
  '15.0(2)EX8',
  '15.0(2a)EX5',
  '15.0(2)EX10',
  '15.0(2)EX11',
  '15.0(2)EX13',
  '15.0(2)EX12',
  '15.2(3)GC',
  '15.2(3)GC1',
  '15.2(4)GC',
  '15.2(4)GC1',
  '15.2(4)GC2',
  '15.2(4)GC3',
  '15.1(1)SY',
  '15.1(1)SY1',
  '15.1(2)SY',
  '15.1(2)SY1',
  '15.1(2)SY2',
  '15.1(1)SY2',
  '15.1(1)SY3',
  '15.1(2)SY3',
  '15.1(1)SY4',
  '15.1(1)SY5',
  '15.1(1)SY6',
  '15.1(2)SY6',
  '15.1(2)SY7',
  '15.1(2)SY8',
  '15.1(2)SY9',
  '15.1(2)SY10',
  '15.1(2)SY11',
  '15.3(1)S',
  '15.3(2)S',
  '15.3(3)S',
  '15.3(1)S2',
  '15.3(1)S1',
  '15.3(2)S2',
  '15.3(2)S1',
  '15.3(1)S1e',
  '15.3(3)S1',
  '15.3(3)S2',
  '15.3(3)S3',
  '15.3(3)S6',
  '15.3(3)S4',
  '15.3(3)S1a',
  '15.3(3)S5',
  '15.3(3)S2a',
  '15.3(3)S7',
  '15.3(3)S8',
  '15.3(3)S6a',
  '15.3(3)S9',
  '15.3(3)S10',
  '15.3(3)S8a',
  '15.4(1)T',
  '15.4(2)T',
  '15.4(1)T2',
  '15.4(1)T1',
  '15.4(1)T3',
  '15.4(2)T1',
  '15.4(2)T3',
  '15.4(2)T2',
  '15.4(1)T4',
  '15.4(2)T4',
  '15.2(1)E',
  '15.2(2)E',
  '15.2(1)E1',
  '15.2(3)E',
  '15.2(1)E2',
  '15.2(1)E3',
  '15.2(2)E1',
  '15.2(2b)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(2)E2',
  '15.2(2a)E1',
  '15.2(2)E3',
  '15.2(2a)E2',
  '15.2(3)E2',
  '15.2(3a)E',
  '15.2(3)E3',
  '15.2(3m)E2',
  '15.2(4)E1',
  '15.2(2)E4',
  '15.2(2)E5',
  '15.2(4)E2',
  '15.2(4m)E1',
  '15.2(3)E4',
  '15.2(5)E',
  '15.2(3m)E7',
  '15.2(4)E3',
  '15.2(2)E6',
  '15.2(5)E1',
  '15.2(5b)E',
  '15.2(4m)E3',
  '15.2(3m)E8',
  '15.2(2)E5a',
  '15.2(3)E5',
  '15.2(2)E5b',
  '15.2(4n)E2',
  '15.2(4o)E2',
  '15.2(5a)E1',
  '15.2(4)E4',
  '15.2(2)E7',
  '15.2(5)E2',
  '15.2(4p)E1',
  '15.2(6)E',
  '15.2(5)E2b',
  '15.2(4)E5',
  '15.2(5)E2c',
  '15.2(4m)E2',
  '15.2(4o)E3',
  '15.2(4q)E1',
  '15.2(6)E0a',
  '15.2(6)E0b',
  '15.2(2)E7b',
  '15.2(4)E5a',
  '15.2(6)E0c',
  '15.2(4s)E1',
  '15.2(4s)E2',
  '15.4(1)S',
  '15.4(2)S',
  '15.4(3)S',
  '15.4(1)S1',
  '15.4(1)S2',
  '15.4(2)S1',
  '15.4(1)S3',
  '15.4(3)S1',
  '15.4(2)S2',
  '15.4(3)S2',
  '15.4(3)S3',
  '15.4(1)S4',
  '15.4(2)S3',
  '15.4(2)S4',
  '15.4(3)S0d',
  '15.4(3)S4',
  '15.4(3)S0e',
  '15.4(3)S5',
  '15.4(3)S0f',
  '15.4(3)S6',
  '15.4(3)S7',
  '15.4(3)S6a',
  '15.4(3)S8',
  '15.3(3)M',
  '15.3(3)M1',
  '15.3(3)M2',
  '15.3(3)M3',
  '15.3(3)M5',
  '15.3(3)M4',
  '15.3(3)M6',
  '15.3(3)M7',
  '15.3(3)M8',
  '15.3(3)M9',
  '15.3(3)M10',
  '15.3(3)M8a',
  '15.0(2)EZ',
  '15.2(1)SC1a',
  '15.2(2)SC',
  '15.2(2)SC1',
  '15.2(2)SC3',
  '15.2(2)SC4',
  '15.2(1)EY',
  '15.0(2)EJ',
  '15.0(2)EJ1',
  '15.2(1)SY',
  '15.2(1)SY1',
  '15.2(1)SY0a',
  '15.2(1)SY2',
  '15.2(2)SY',
  '15.2(1)SY1a',
  '15.2(2)SY1',
  '15.2(2)SY2',
  '15.2(1)SY3',
  '15.2(1)SY4',
  '15.2(2)SY3',
  '15.2(1)SY5',
  '15.4(3)M',
  '15.4(3)M1',
  '15.4(3)M2',
  '15.4(3)M4',
  '15.4(3)M5',
  '15.4(3)M6',
  '15.4(3)M7',
  '15.4(3)M6a',
  '15.4(3)M7a',
  '15.4(3)M8',
  '15.2(1)SD1',
  '15.2(1)SD2',
  '15.2(1)SD3',
  '15.2(1)SD4',
  '15.2(1)SD6',
  '15.2(1)SD6a',
  '15.2(1)SD7',
  '15.2(1)SD8',
  '15.2(4)JAZ1',
  '15.0(2)EK',
  '15.0(2)EK1',
  '15.3(3)XB12',
  '15.4(1)CG',
  '15.4(1)CG1',
  '15.4(2)CG',
  '15.5(1)S',
  '15.5(2)S',
  '15.5(1)S1',
  '15.5(3)S',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(2)S3',
  '15.5(3)S2',
  '15.5(3)S0a',
  '15.5(3)S3',
  '15.5(1)S4',
  '15.5(2)S4',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)S6',
  '15.5(3)S6a',
  '15.5(3)S6b',
  '15.2(2)EB',
  '15.2(2)EB1',
  '15.2(2)EB2',
  '15.5(2)T',
  '15.5(1)T3',
  '15.5(2)T1',
  '15.5(2)T2',
  '15.5(2)T3',
  '15.5(2)T4',
  '15.5(1)T4',
  '15.2(2)EA',
  '15.2(2)EA1',
  '15.2(2)EA2',
  '15.2(3)EA',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(2)EA3',
  '15.2(4)EA3',
  '15.2(5)EA',
  '15.2(4)EA4',
  '15.2(4)EA2',
  '15.2(4)EA5',
  '15.2(4)EA6',
  '15.4(2)SN',
  '15.4(2)SN1',
  '15.4(3)SN1',
  '15.4(3)SN1a',
  '15.5(3)M',
  '15.5(3)M1',
  '15.5(3)M0a',
  '15.5(3)M2',
  '15.5(3)M2a',
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M5',
  '15.5(3)M4b',
  '15.5(3)M4c',
  '15.5(3)M6',
  '15.5(3)M5a',
  '15.5(3)M6a',
  '15.3(3)JAA1',
  '15.5(1)SN',
  '15.5(1)SN1',
  '15.5(2)SN',
  '15.5(3)SN0a',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(2)S0a',
  '15.6(2)S2',
  '15.6(1)S3',
  '15.6(2)S3',
  '15.6(1)S4',
  '15.6(2)S4',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T0a',
  '15.6(2)T2',
  '15.6(1)T3',
  '15.6(2)T3',
  '15.3(1)SY',
  '15.3(0)SY',
  '15.3(1)SY1',
  '15.3(1)SY2',
  '15.3(1)SY3',
  '15.6(2)SP',
  '15.6(2)SP1',
  '15.6(2)SP2',
  '15.6(2)SP3b',
  '15.6(1)SN',
  '15.6(1)SN1',
  '15.6(2)SN',
  '15.6(1)SN2',
  '15.6(1)SN3',
  '15.6(3)SN',
  '15.6(4)SN',
  '15.6(5)SN',
  '15.6(6)SN',
  '15.6(7)SN',
  '15.6(7)SN1',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.2(4)EC1',
  '15.2(4)EC2',
  '15.4(1)SY',
  '15.4(1)SY1',
  '15.4(1)SY2',
  '15.4(1)SY3',
  '15.5(1)SY',
  '15.7(3)M',
  '15.7(3)M0a'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ip_sla'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvf37838'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
