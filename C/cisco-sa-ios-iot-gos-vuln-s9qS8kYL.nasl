#TRUSTED 35d337aa223fa64834bae9008ef5e3b467792bc47c5b16c071596ed29a679a327697dbc45b6f160193a94cc9eb68fd914b135138b0c3948cee3f352075864c3b88770698e23353516268795ff48b35a6d7fcd52465d4ce56e90fafbf2b1bd8f5110100355d243c61c1ec69f9c81d6c52a0e5cf74ab1c37c274e89e008d4778659d5f7441eeb0a070a4913b8e7f013f7f7790b9d7b288b0fb582a97e257d027457ee8f9c6ece486616fb76f6200b177666d794182c8fd70b66c461b7fbc9f94b90d0dd271031f7deecfa05718efdbaedf33fa963d1fa2f866da332f468de0eaac6d1a669beb4a1a869bf2d64fa2fa12d5e2a2d86251bd37e09ac2eee77324deac79b753365a2095df1ee1a4cfd938c4b04e11f606767fe0211922b699f240e5a37cdb61cabbea8dbc3387baa21c786498c8841071e8b71989dbf706fba03e72d67904e82754fc6285f3a449e725c749fec55605d7cc7e8b44d761a9c367d210f7b297ccd7ec6b47c53c6eec8bd92b77b6869d4f579dd769588718fe70a65080443aa50e22d70105b77b38c3607c387396ec00e0517d2925d34045c1fd66be618ba7dc68f575059b7094b10495076e7f4ca8fcf5a936e7612d70ee292d2c294bd2fe50c5a64ab41c61c55c5e324ff3ba8e96617e3c76d5078417fbf158436cbd9db83902752de9ebab77ca78cbac11362a132b79fe64a6ff577a866530b6a6c229
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139037);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3199", "CVE-2020-3257");
  script_xref(name:"IAVA", value:"2020-A-0239-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq68872");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr15042");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-iot-gos-vuln-s9qS8kYL");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOx Application Environment for IOS Software for Cisco Industrial Routers Multiple Vulnerabilities (cisco-sa-ios-iot-gos-vuln-s9qS8kYL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is affected by multiple vulnerabilities in the IOx
application environment of Cisco 809 and 829 Industrial Integrated Services Routers (Industrial ISRs) and Cisco 1000
Series Connected Grid Routers (CGR1000). Attackers can exploit these in order to cause a DoS condition or execute
arbitrary code with elevated privileges on an affected device, as follows:

  - A local, low privileged attacker can execute arbitrary code in an affected system with high privileges
    due to incorrect bounds checking of certain type, length, value (TLV) fields of signaling packets that
    are exchanged between Cisco IOS Software and a Guest OS. This can be exploited by authenticating to the
    device by using low-privileged user credentials and then sending crafted packets, which when processed
    can create an exploitable buffer overflow condition. (CVE-2020-3257)

  - An authenticated, adjacent attacker can cause a DoS condition due to a vulnerability in the ingress
    packet processing functionality of Cisco IOS Software due to insufficient isolation of an internal,
    emulated Ethernet interface. This can be exploited by sending malicious IP packets. (CVE-2020-3199)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-iot-gos-vuln-s9qS8kYL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?575acf13");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq68872");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr15042");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr15042 and CSCvq68872");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3199");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

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
model = product_info['model'];


if (model !~ 'ISR8[02]9([^0-9]|$)' &&
    model !~ 'CGR.*[^0-9]1[0-9]{3}([^0-9]|$)'
    )
  audit(AUDIT_HOST_NOT, 'an affected model');

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
  '15.5(3)M11',
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
  '15.6(3)M8',
  '15.6(3)M9',
  '15.7(3)M',
  '15.7(3)M1',
  '15.7(3)M3',
  '15.7(3)M2',
  '15.7(3)M4',
  '15.7(3)M5',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.7(3)M6',
  '15.7(3)M7',
  '15.8(3)M',
  '15.8(3)M1',
  '15.8(3)M0a',
  '15.8(3)M2',
  '15.8(3)M3',
  '15.8(3)M2a',
  '15.8(3)M4',
  '15.8(3)M3a',
  '15.8(3)M3b',
  '15.8(3)M5',
  '15.9(3)M',
  '15.9(3)M0a',
  '15.3(3)JPJ'
);

# Checking for Guest OS enabled will cover both workarounds: for the other, the workaround configuration can only be 
# set when Guest OS is not in use.
workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ios_iox_host_list'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr15042, CSCvq68872'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
