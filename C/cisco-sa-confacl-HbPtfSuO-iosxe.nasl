#TRUSTED 4dbbd2a3b02ec31bf10d2c9770bc3335725c542ed1787f6b9c657a80478c9453a0e1ce057501798480f0723db3a73496e3bc0ae9f8aad1e2aaa394aecb6550e4d2df72a71da59796504b943e301730440b7d629123692bda5e46d803b8d68d6dcc6f916a6f9f1883cc3c088dcb4af96d2c674c35d4b3bdb75d999b45df1ee3f5cacd5b4200e2d28939ca605f5158d8dac854c61a5112214408368e334a8758d56400087e9a41ab7b027ff9cc908b1d8b9fa024d2e56572d3e46cadfcc1faa0f574b5c65bbd92f5304a3acbf88a9a577abcdd840815026e2102faa4fd860feb323628f08a92f5f1a5e7885f5d4c26f4efc952e4c13b135d7699695ed181bc40c6471716995c44317c028df70a010e4aed2574aef61695094d91c7da6f07ce8dce72645ed63007f1b914e0c703f086342b83f436a65b29fb6c4daa25dcfbde119a459bc7190695ef94335216593f434e7f93fee78d1914a340414f48bc1153834686117dbc59c142faa3c5f8c8f57e78ddfeeed071c2779d093aab310dcaf792d29fedfb8d9a5f4b6d8b917cc87f30f46970444c5ffa86c989ba7e883144e17c099174994638f723ae15b1a74dffb79f87f1a757fc39a0a25e462c0987291278a6f3a52668363f2649125b3b31330ff1f47c65e5b87d6415f36d55a11539872f76ca333193e7ab3c128920a228302b26d6bcb56a6d4e52bf718e638a0bcc5db551
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141499);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3407");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs72434");
  script_xref(name:"CISCO-SA", value:"cisco-sa-confacl-HbPtfSuO");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software RESTCONF NETCONF YANG Access Control List DoS (cisco-sa-confacl-HbPtfSuO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a denial of service (DoS) vulnerability in the RESTCONF
and NETCONF-YANG access control list (ACL) function. An unauthenticated, remote attacker can exploit this, by accessing
the device using RESTCONF or NETCONF-YANG to cause the device to reload, causing a DoS condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-confacl-HbPtfSuO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1e90eb4");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs72434.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.2.1',
  '17.2.1a',
  '17.2.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['netconf_restconf_acl_size_13']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs72434',
  'cmds'     , make_list('show running-config', 'show access-lists')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
