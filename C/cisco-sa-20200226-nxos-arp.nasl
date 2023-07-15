#TRUSTED a737caaed4858a1040089b8f8bf594a80d83cd5897dcac9a039a48ba02724e45981f4bed86701277e0bd9a778bb0350c9c10b56f595fcff40d2ea9b1b0239e3d8143fb1004a4a756e5ef501959d96916cc7c52ef4da9eadc82406c70d34c3055ba5f0b4db59cd25037a684c38e5c94238cb7dbc6c6c4773e80cd9e617851118956d9898eb5c82e05230c9a73f496f8cffd7ed772d21c1c1c0693e9e4c1d1b29045dacbc754a541b19f1a21b6ec25f17a50d8af6b645a2d8cb88980354dac936983faae03249246f31d8d6f23d37fb52ea008ea58dba21437379d56aea9755178d6a6626b6fcdb2fa67d079bb551d211fcab5e68202a01bf1d8de3c3ded2d7029f78ca3b5c40dc11fc2ce54b1a9dda21328f896d733314447bffe2cd9a645f69935077039afb109406af3154838504b9f045cf61f74340f48f8849797591b3c0070c38f7efef23470c4ce8056e58889a92df947d8e9d518ea7bbd9e9638f105961c04029bfac94eac6a9a7c40be2d8c96ee5bc760909cba616f7e5e7690fdc9826190833afa69c53d1301570c35e90e75b58b014af602ae2960d8b04244e1d2e454614187d02e30a9ec097b1c4060bff166d5c2504ec97200cf7144d33132428d8ea1265f4689ba78843749615d97212b81217ce0d03553bf2a0e6a758b5b64e28b26b07c9f070e12de7f2db8305184ec8db13647d472ff3fa5aa973037b5d3f1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134229);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/07");

  script_cve_id("CVE-2020-3174");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq48220");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-nxos-arp");
  script_xref(name:"IAVA", value:"2020-A-0087");

  script_name(english:"Cisco NX-OS Software Anycast Gateway Invalid ARP Vulnerability (cisco-sa-20200226-nxos-arp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-nxos-arp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1aa6dcf2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq48220");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq48220");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3174");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(345);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if('Nexus' >!< product_info.device || product_info.model !~ '^[379][0-9]{3}')
  audit(AUDIT_HOST_NOT, 'affected');

# CVRF asserts vulnerable versions of specific models
if (product_info.model =~ '^3')
{
  version_list = make_list(
    '9.2(1)',
    '9.2(2)',
    '9.2(2t)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.2(2v)',
    '9.3(1)'
  );
}
else if (product_info.model =~ '^7')
{
  version_list = make_list(
    '7.3(2)D1(1d)',
    '8.0(1)',
    '8.1(1)',
    '8.1(2)',
    '8.1(2a)',
    '8.2(1)',
    '8.2(2)',
    '8.2(3)',
    '8.2(4)',
    '8.3(1)',
    '8.3(2)',
    '8.4(1)'
  );
}
else # 9x
{
  version_list = make_list(
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.3(1)',
    '9.3(1z)'
  );
}

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['anycast-gateway'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info.version,
  'bug_id'   , 'CSCvq48220',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
