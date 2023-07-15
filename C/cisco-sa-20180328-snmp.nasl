#TRUSTED 841145f6e5726173bc3f89f155df37c06fb634e16e291ee2a862b0b3ab0c30729310ec0b2e0bfeb0f0159a5f48f36da96eaa3d45d170bc929639f03fd5721a857a823a635d7ee150326dd788cfdbaeec943226d0eeaa19c4ec77779549380e9a51967942e43eb998c2352117dc4c1037f2884d914ecc51fbd9cc8fb7a792319f4fe901fcd36e0a088e429b68402830f8db2817be77a372c9d1cce16391e35b5691b38efefdb01ad9ffb91330b62160fb19824c98b95ed48a8c09e9a401b90cb679ad1624a2cc32ac2b4d0f49a373c32abd686a83777719549241115a64cb03ef4a6757bcfffac1022dd5124b17c279e825c84a7acbdf8d4f305bf48d6edef978af2ddfeb69e725c19425c37ba3e91442cc2815faa7ef1aaf62230e4066725d44adb24b642c53ab81f2e1f245c9d01f33acbf54ba02e5a501100e82d0dbcd3ab17fb358154c03132e5a099ed060e4a403670bdfafd7421628eec3f0712e2ed27ef234d76f4f1cb94519931c545281816065cabdd4503a12957530a61a92e87f0c3e8f374a88d21f5af8c230ef9df293a5748b68d82fe1952bf1f784a339c9f98a7529660b85f5bf5cc9ed4b7042d774d96f11722f74f81e6c4dd10a98c6504418b38543638078665b5f90396b9086c874e68358625f8282119feedc9c6582ff1cc54e70cc94db6eeef8374ba7b8750b7b1c0cf87573ff848741ef0ede647179cb
#TRUST-RSA-SHA256 47a2735af68e437ef64ae4c6b78693e12a7070663e38bc5eb09cfaaec0b83aa6402538476a0de14811c1deb989f5239cb9950c75a22cdfbb50f2f333087b8a8b22061121a6a05d77ccf4bc6e6c19d1ab0bb8e3ec3cbf9448fa1e756d297575c0656c3231765a5812818692c76acf65ae1f87e629475e37bb370477c2a18f042c6ff985d0a850200baf834d68979f7edeca40e2012895b79434a05e5e011eef0c64954d07c98293b2d423b456ea570787e809e80192496e37f7e05f058f14d671eb7765c99656407cfad94f61808785774664bbf8353252bf7826edd0599997e07eead01ec0b0851620d2563c8c16c305819f4b95b70262e85932404645a2f58daecd89d1d53b2c9c2d5e87081949d756bb619488b174129302c9ac9d3e1a245a14203287008340e306b3f50b3225ebaeefc7be2db8b4038a96268b79ad9dc599c2cae48ff852f50221c3c9863761ba8b1b8e7e290a1230a4fd13f38c44b6e6f248618bcb735586309790450ff17c5b986ee28de8ef08393712ab7b99ec6b2d0fae85b1c18a7e02b5e854c8c76de34c1881c6b944ed6bb7414526f9faeef1624af49cbeeadc664898e687df31f670b09a249b794b290133c757e6ca1bf3382f77ffee2f67a7a90493239993403cd02a967d996789ef8a5cf505cfc1f814165c126e735e948715a30595755c62cf6a7394b900b964707850f50f850efba4757777
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131324);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0161");
  script_bugtraq_id(103573);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd89541");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-snmp");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS Software Simple Network Management Protocol GET MIB Object ID DoS (cisco-sa-20180328-snmp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a denial of service (DoS) vulnerability in the Simple
Network Management Protocol (SNMP) subsystem running on certain models of Cisco Catalyst Switches due to a condition
that could occur when the affected software processes an SNMP read request that contains a request for the ciscoFlashMIB
object ID (OID). An authenticated, remote attacker can exploit this, by issuing an SNMP GET request for the
ciscoFlashMIB OID on an affected device in order to cause the device to restart due to a SYS-3-CPUHOG.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-snmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?61dd3327");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd89541");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvd89541.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0161");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

if (
    product_info.model !~ "(^|[^0-9])2960L" &&
    product_info.model !~ "CDB-8P" &&
    product_info.model !~ "CDB-8U"
   )
  audit(AUDIT_HOST_NOT, "affected");

version_list = make_list(
  '15.2(5)E',
  '15.2(5a)E',
  '15.2(5)E1',
  '15.2(5b)E',
  '15.2(5c)E',
  '15.2(5a)E1',
  '15.2(5)E2',
  '15.2(5)E2b',
  '15.2(5)E2c',
  '15.2(5)EX',
  '15.2(5)EA',
  '15.6(2)SP3b'
);

workarounds = make_list(CISCO_WORKAROUNDS['snmp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd89541',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
