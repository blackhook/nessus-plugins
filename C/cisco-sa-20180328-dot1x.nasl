#TRUSTED a4f477cfd995775e5f5a31de640d5531eee00c40a9ebf87768bba466fb3637b51c1f5d92f60ff1d0738e2ec3bc798246221c3b6f32d16e60d94764ce2b53a81a9b8e430f5afbf6dca3e3956855a1f51d9f5300ad4fef02e501ae72686107a623b1b373624aa293e6a6199f3a72d922ecd2ef7c7d3b2ffc793907594dc2cfb19846f2322a8c46599aeb6a7ade6c53512598456febb3409c9848ebe5163983dbeadde3c543f270e31b679ff5517a8ab123555fe0ee7a4740bf8e248bf34e8e4c6738adf6b94dfcd2e8f522324e4f49d520da8f7402e37154e21717b4044ba213e99ab262edf92d9549857a3cf463e07442837ea1fc587f64b9ff0a9ad149ac78ce3315413f8c836d3facfa4a8ebebab763d3ab690b25998190235d38d61b6c4be67072e3b7e1365cadc27a5a5d7e12daf8c8bd2198df3baf58f569c15d977918bf70e876117c29a7698e13488c0ae2dbbe5bc6034f386a3b823a1dd66ff46051dd5981371e879ccb4dca7356b9b9745bd1dee7efec61f849e71ada457622905767b9d3e777f473af2f3ff0d5be8eba6a3d0af6344cfc0a4082c7140a1e7eeaef2c3e50c08b8ad61e94a466c68441efb62ca27bf5cd2aa690910846454ce3cdd87f563b780f63a28ef743999fdb1a8e03f558794aa5c6770b4ff98bffe61fbad68de91a3364792d3a3e7f2be4b9bd4e3db244d2d9eb121186af5349242757f3fd32
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131400);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/02");

  script_cve_id("CVE-2018-0163");
  script_bugtraq_id(103571);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg69701");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-dot1x");

  script_name(english:"Cisco IOS Software 802.1x Multiple-Authentication Port Authentication Bypass (cisco-sa-20180328-dot1x)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by an authentication bypass vulnerability in the 802.1x
multiple-authentication (multi-auth) feature due to a logic change error introduced into the code. An unauthenticated,
adjacent attacker could exploit this, by trying to access an 802.1x multi-auth port after a successful supplicant has 
authenticated, to bypass the authentication phase on an 802.1x multi-auth port and obtain access to the network.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-dot1x
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?caa45e0a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg69701");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvg69701.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0163");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

# Version list comes from bug ID page, so this script is paranoid
if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list = make_list(
  '15.4(3)M6',
  '15.4(3)M6a',
  '15.4(3)M7',
  '15.4(3)M7a',
  '15.4(3)M8',
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M4b',
  '15.5(3)M4c',
  '15.5(3)M5',
  '15.5(3)M5a',
  '15.5(3)M6',
  '15.5(3)M6a',
  '15.6(3)M',
  '15.6(3)M0a',
  '15.6(3)M1',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M2a',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(1)T2',
  '15.6(1)T3',
  '15.6(2)T1',
  '15.6(2)T2',
  '15.6(2)T3',
  '15.7(3)M',
  '15.7(3)M0a',
  '15.7(3)M1',
  '15.7(3)M2'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['dot1x_multi-auth'];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg69701'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params
);
