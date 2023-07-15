#TRUSTED 94229729146ac0e3009f15cacc2c3a3df5f50d4de3181e3532ca6f0985e42a886034455ec0841f2082b6984b551d8cd7497b361ac164eb4aa7c8a05d712440bf5d0bfe2d6b62ed8e486546520635da6038ae994d65f010323a5fad10981d37714a8ff92b52a3013dc915f92dba2fd15928056385d838392b8a59c75bbc4159d2208751d7b2cddfb6fbff9a947b12cfb84851d9e6f84b6118a1fc27dfe21129492255dfe3453aca20c85aafed2eccdd5bad2eda3e04671d392a365a7926719b01c55e52b9ed638506f33c2994cbad2cdd0f8135247d17a10e55fc5ef752569b411cca826d0e571bb60c5770671a2c1440144a9fda0be1eee5818b55d2e30f668c9f679b2e419fd085745528870def1ee5f7ba1be4bec090f4efeb94b3032fbb68bcd8831d9693f91c67c9761238d81a7d36eccfb60207d14f1b7381ae150e31ed88d7130bfba7f957289d630ca6235803c5f31a25e7887fb36462943ade351f29a077da66b8d19d61b2ccb8d9b5501d9b7de7abf1a884aafa4aa7b210f19fba167b20ed286ce59be3582d6a626ab867142f58ee55daacfdded2bfd1aa4c2380103916c22930ab950f4dac4b46bf61145f8e78aef7b80adeb9862d868502083099954eb9edb6233e9d38467071921f31711601c651ed0912342711a30ac1530ca8bd577390fd3ae957c2e721535c87ecb37157456adc1269e3f1790b45d3185527
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129812);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2019-1752");
  script_bugtraq_id(107589);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz74957");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk01977");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-isdn");

  script_name(english:"Cisco IOS ISDN Interface Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is affected by a vulnerability in the ISDN functions which
could allow an unauthenticated, remote attacker to cause the device to reload. The vulnerability is due to incorrect
processing of specific values in the Q.931 information elements. An attacker can exploit this vulnerability by calling
the affected device with specific Q.931 information elements being present. An exploit could allow the attacker to cause
the device to reload, resulting in a denial of service (DoS) condition on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-isdn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6adb46b3");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz74957");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk01977");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuz74957 and CSCvk01977");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

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
	'15.0(1)M1',
	'15.0(1)M5',
	'15.0(1)M4',
	'15.0(1)M3',
	'15.0(1)M2',
	'15.0(1)M6',
	'15.0(1)M',
	'15.0(1)M7',
	'15.0(1)M10',
	'15.0(1)M9',
	'15.0(1)M8',
	'15.0(1)M6a',
	'15.0(1)XA2',
	'15.0(1)XA4',
	'15.0(1)XA1',
	'15.0(1)XA3',
	'15.0(1)XA',
	'15.0(1)XA5',
	'15.1(2)T',
	'15.1(1)T4',
	'15.1(3)T2',
	'15.1(1)T1',
	'15.1(2)T0a',
	'15.1(3)T3',
	'15.1(1)T3',
	'15.1(2)T3',
	'15.1(2)T4',
	'15.1(1)T2',
	'15.1(3)T',
	'15.1(2)T2a',
	'15.1(3)T1',
	'15.1(1)T',
	'15.1(2)T2',
	'15.1(2)T1',
	'15.1(2)T5',
	'15.1(3)T4',
	'15.1(1)T5',
	'15.1(1)XB',
	'15.1(1)XB3',
	'15.1(1)XB1',
	'15.1(1)XB2',
	'15.1(4)XB4',
	'15.1(4)XB5',
	'15.1(4)XB6',
	'15.1(4)XB5a',
	'15.1(4)XB7',
	'15.1(4)XB8',
	'15.1(4)XB8a',
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
	'15.1(4)M3',
	'15.1(4)M',
	'15.1(4)M1',
	'15.1(4)M2',
	'15.1(4)M6',
	'15.1(4)M5',
	'15.1(4)M4',
	'15.1(4)M0a',
	'15.1(4)M0b',
	'15.1(4)M7',
	'15.1(4)M3a',
	'15.1(4)M10',
	'15.1(4)M8',
	'15.1(4)M9',
	'15.1(4)M12a',
	'15.1(2)GC',
	'15.1(2)GC1',
	'15.1(2)GC2',
	'15.1(4)GC',
	'15.1(4)GC1',
	'15.1(4)GC2',
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
	'15.2(1)GC',
	'15.2(1)GC1',
	'15.2(1)GC2',
	'15.2(2)GC',
	'15.2(3)GC',
	'15.2(3)GC1',
	'15.2(4)GC',
	'15.2(4)GC1',
	'15.2(4)GC2',
	'15.2(4)GC3',
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
	'15.4(2)S3',
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
	'15.4(3)M',
	'15.4(3)M1',
	'15.4(3)M2',
	'15.4(3)M3',
	'15.4(3)M4',
	'15.4(3)M5',
	'15.4(3)M6',
	'15.4(3)M7',
	'15.4(3)M6a',
	'15.4(3)M7a',
	'15.4(3)M8',
	'15.4(3)M9',
	'15.4(3)M10',
	'15.3(3)XB12',
	'15.4(1)CG',
	'15.4(1)CG1',
	'15.4(2)CG',
	'15.5(1)T',
	'15.5(1)T1',
	'15.5(2)T',
	'15.5(1)T2',
	'15.5(1)T3',
	'15.5(2)T1',
	'15.5(2)T2',
	'15.5(2)T3',
	'15.5(2)T4',
	'15.5(1)T4',
	'15.5(3)M',
	'15.5(3)M1',
	'15.5(3)M2',
	'15.5(3)M2a',
	'15.5(3)M3',
	'15.5(3)M4',
	'15.5(3)M4a',
	'15.5(3)M5',
	'15.5(3)M4b',
	'15.5(3)M4c',
	'15.5(3)M5a',
	'15.6(1)T',
	'15.6(2)T',
	'15.6(1)T0a',
	'15.6(1)T1',
	'15.6(2)T1',
	'15.6(1)T2',
	'15.6(2)T2',
	'15.6(1)T3',
	'15.6(2)T3',
	'15.5(2)XB',
	'15.6(3)M',
	'15.6(3)M1',
	'15.6(3)M0a',
	'15.6(3)M1a',
	'15.6(3)M1b',
	'15.6(3)M2',
	'15.6(3)M2a',
	'15.6(3)M3',
	'15.6(3)M3a',
	'15.6(3)M4',
	'15.6(3)M5',
	'15.7(3)M',
	'15.7(3)M1',
	'15.7(3)M0a',
	'15.7(3)M3',
	'15.7(3)M2',
	'15.8(3)M',
	'15.8(3)M0a'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['isdn'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuz74957, CSCvk01977',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
