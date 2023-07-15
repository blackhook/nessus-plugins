#TRUSTED 96943621f54933107c300faf401200c3a5f86d20449bf5a8bb8a687bab50c120401df714c34b135201cdf36d0d9732c0f0f8fb4cb61eb86867badcff335c367326af46af4a2cd2ac60db3eba07cfa05887ea5062a3f6d307ca9471d5495c63f53102c8c060dea37235914a0a278965e33a151b086ec73cd84ed582d9d7d0fce9313986ee0f3a3e661b34cbb639d4c11157a03ff555affb675a904f8abc377f978fd725622f648e7bfbeea5c3b0cf7cc5b126913604090cd2e2dabd37b0552e91bb31cfba39af950d79ae05543ef3eff60cdf4e79d5700a32217fe4d5d97414b6236b885d2f87fec2096af187dd482007457ab27e5f8742c4388f39c2b4ffa0cb0c4947439476fb5e1614686ad7a6356f8fb0a32e2dce61519af69aa567dd1fe432afa25c35394a2e7f0e566b572fc317d64f3371c940175d8af619b21aeff2c2ef99ebb43dd0b4b8220e4146f744597436d776c651e4fda79f96272a8dd7b01768bbd9a02f81a28878017191ae77725ec3d7b25d9d63fc2732e8593ea5a1146ec20e0016054809f9680f3561bd167bd0c1b1d88e1150ba196b082a064425cd47b3e42a382f11ba7b7f8fbd17e9d6e01d93801d88846a49c5a6821cdf4dd0fcd3fe89e74c9f6dcc0fa2a195688cd44299c215aa2e37dd3c2b20d19bcc33f85afde202564385bc95d4c3f9f2dd46a2ef5b020a041d4c6392342947997c141b6b34
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139614);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3198", "CVE-2020-3258");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr12083");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr46885");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-iot-rce-xYRSeMNH");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS Software for Cisco Industrial Routers Arbitrary Code Execution Vulnerabilities (cisco-sa-ios-iot-rce-xYRSeMNH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software for Cisco 809 and 829 Industrial Integrated Services Routers
(Industrial ISRs) and Cisco 1000 Series Connected Grid Routers (CGR1000) is affected by multiple arbitrary code
execution vulnerabilities, as follows:

  - A vulnerability in the area of code that manages inter-VM signaling due to incorrect bounds checking. An
    unauthenticated, remote attacker can exploit this, by sending malicious packets to an affected device, in
    order to execute arbitrary code on an affected system or cause the system to crash and reload.
    (CVE-2020-3198)

  - A vulnerability in one of the diagnostic test CLI commands. This exists because, under specific
    circumstances, the affected software permits the modification of the device's run-time memory. An
    authenticated, local attacker can exploit this, by authenticating to the targeted device and issuing
    a specific diagnostic test command at the CLI in order to execute arbitrary code on an affected device.
    (CVE-2020-3258)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-iot-rce-xYRSeMNH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0db8a62");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr12083");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr46885");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco bug IDs CSCvr12083 and CSCvr46885");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3198");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/17");

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

product_info = cisco::get_product_info(name:'Cisco IOS');

# This vulnerability affects Cisco 809 and 829 Industrial ISRs and CGR1000
if (toupper(product_info['model']) !~ "^IR8[0-9]{2}([^0-9]|$)" &&
    toupper(product_info['model']) !~ "CGR.*1[0-9]{3}([^0-9]|$)")
  audit(AUDIT_HOST_NOT, 'affected');

# It looks like we might get IR800 for IR809, IR829, or IR800 - so make this paranoid.
# According to: https://www.cisco.com/c/en/us/td/docs/routers/access/800/829/15-8-3M2-Release-Note.html
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

version_list=make_list(
  '12.2(60)EZ16',
  '15.0(2)SG11a',
  '15.4(3)M',
  '15.4(3)M1',
  '15.4(3)M2',
  '15.4(3)M3',
  '15.4(3)M4',
  '15.4(3)M5',
  '15.4(3)M6',
  '15.4(3)M7',
  '15.4(3)M6a',
  '15.4(3)M8',
  '15.4(3)M9',
  '15.4(3)M10',
  '15.4(1)CG',
  '15.4(2)CG',
  '15.5(1)T',
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
  '15.5(3)M0a',
  '15.5(3)M2',
  '15.5(3)M2a',
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M5',
  '15.5(3)M6',
  '15.5(3)M7',
  '15.5(3)M6a',
  '15.5(3)M8',
  '15.5(3)M9',
  '15.5(3)M10',
  '15.3(3)JAA1',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T2',
  '15.6(1)T3',
  '15.6(2)T3',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)M6',
  '15.6(3)M7',
  '15.6(3)M6a',
  '15.6(3)M6b',
  '15.7(3)M',
  '15.7(3)M1',
  '15.7(3)M3',
  '15.7(3)M2',
  '15.7(3)M4',
  '15.7(3)M5',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.8(3)M',
  '15.8(3)M1',
  '15.8(3)M0a',
  '15.8(3)M2',
  '15.8(3)M3',
  '15.8(3)M2a',
  '15.8(3)M3a',
  '15.8(3)M3b',
  '15.9(3)M',
  '15.9(3)M0a',
  '15.3(3)JPJ'
);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr12083, CSCvr46885',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  router_only:TRUE
);

