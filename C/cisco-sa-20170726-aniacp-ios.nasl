#TRUSTED 01ac37fc4bdf916955edded913e101a3393e7b9feddc4ef7cdb1700241e147b31a1a11e73b525da7a26f627b0e1e80ff2d1de25e285162d423984aa8035dd468237cf0b0305824449ade8460bb642dabbf332ef1581b72d5924c88095ca60dfcd0ddcce2a0914dc27b73d312d50eb2f74a5db289a336e2bba9730ed248074a459c1a02dd95d6af3222be11a38e3bec07290a67ef53b592d63d4895defe3ec784423efcc8ac62e9ad0f110f7b2d17b763b5d8d85bb1e33d4e0f163687eae80a6394e7a7cc4320ec949be02c7198be4287cdffffd6e751764d87e28e8e9afec2a842f53272209703c3e51085f65ecc07f2e336d697d09b33213347ee8b6053b12d9f48ff11b6743fa964163af866ca4f915034e25e5b2a40284c7062f5330fe3916ef7cc9eb512519a338e0686d86418a00767237d1e800f0467c8a59bea93cde5a243927ae969dfbd88a73afadd57e34e7ec34ee84cc5d210e46fe5a2c910340274f6ddfdd390ad89e6e6e7d6ab2370cbb7c20f40ce084f8587626e72017e6c92de9c067411168126eb46821846c8d430f66a093ea40cb82d44edf1f19a9258f8db417a14c53972b45024e1eedfde79fbd946ebbb02bbcd423de51e9ab5714464fc91d1de08daf46d57fe5cf7c91e3d0bd23246375f9200d523222972b1d15393693e8c1de13b8e314d64551ba9a86c4449b98404c5ba136c2f2253be1f941a08
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131079);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/14");

  script_cve_id("CVE-2017-6665");
  script_bugtraq_id(99969);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd51214");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170726-aniacp");

  script_name(english:"Cisco IOS Autonomic Control Plane Channel Information Disclosure (cisco-sa-20170726-aniacp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by an information disclosure vulnerability in the
Autonomic Networking feature due to unknown reasons. An unauthenticated, adjacent attacker can exploit this by capturing
and replaying Autonomic Control Plane (ACP) packets that are transferred within an affected system in order to reset the
ACP of an affected system and cause the system to stop responding. An attacker can also view the ACP packets which
should have been encrypted over the ACP, in clear text.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170726-aniacp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f352f2d4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd51214");
  script_set_attribute(attribute:"solution", value:
"No fixes are available. For more information, see Cisco bug ID(s) CSCvd51214.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/18");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '15.3(3)S2',
  '15.3(3)S6',
  '15.3(3)S1a',
  '15.3(3)S5',
  '15.3(3)S7',
  '15.3(3)S8',
  '15.3(3)S6a',
  '15.3(3)S9',
  '15.3(3)S10',
  '15.3(3)S8a',
  '15.2(3)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3a)E',
  '15.2(3)E3',
  '15.2(3m)E2',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(3)E4',
  '15.2(5)E',
  '15.2(3m)E7',
  '15.2(4)E3',
  '15.2(5)E1',
  '15.2(5b)E',
  '15.2(3m)E8',
  '15.2(3)E5',
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
  '15.5(1)S',
  '15.5(2)S',
  '15.5(1)S1',
  '15.5(3)S',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(3)S1a',
  '15.5(2)S3',
  '15.5(3)S2',
  '15.5(3)S3',
  '15.5(1)S4',
  '15.5(2)S4',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)S6',
  '15.5(3)S6a',
  '15.5(3)S7',
  '15.5(3)S6b',
  '15.5(3)S8',
  '15.5(3)S7a',
  '15.5(3)S7b',
  '15.5(3)S9',
  '15.5(3)S10',
  '15.2(3)EA',
  '15.2(4)EA',
  '15.2(4)EA1',
  '15.2(5)EA',
  '15.2(4)EA4',
  '15.2(4)EA5',
  '15.2(4)EA6',
  '15.4(2)SN',
  '15.4(2)SN1',
  '15.4(3)SN1',
  '15.4(3)SN1a',
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
  '15.6(2)SP',
  '15.6(2)SP1',
  '15.6(2)SP2',
  '15.6(2)SP3',
  '15.6(2)SP4',
  '15.6(2)SP5',
  '15.6(2)SP6',
  '15.6(2)SP7',
  '15.6(2)SP8',
  '15.6(2)SP9',
  '15.6(2)SP8a',
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
  '15.6(7)SN2',
  '15.6(7)SN3',
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
  '15.6(3)M6',
  '15.6(3)M7',
  '15.6(3)M6a',
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
  '15.7(3)M8',
  '15.7(3)M9',
  '15.8(3)M',
  '15.8(3)M1',
  '15.8(3)M0a',
  '15.8(3)M2',
  '15.8(3)M3',
  '15.8(3)M4',
  '15.8(3)M3b',
  '15.8(3)M5',
  '15.8(3)M6',
  '15.8(3)M7',
  '15.9(3)M',
  '15.9(3)M1',
  '15.9(3)M0a',
  '15.9(3)M2',
  '15.9(3)M3'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['autonomic_networking'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd51214',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
