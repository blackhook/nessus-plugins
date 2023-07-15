#TRUSTED 2aaf21115c7e4b78e8c644ed32b5356a0efb961e2402d710383be0d8383e81f42a29fc1d7772c5e294bf94d761192d1f57ee0a61835cbfcc915ca7f091cb3faa2300d882124aee9873ec7c32daea97a4251120451897d82d70f502bfd92e961bc46801be30df88ddf327102545c4e1679ab2e7fae0b9912a9ddcaff88707dfffa3300fd2b3e5b0d61cfa2c4be244a6b86f4c7a5737e923a2201c44859e3159bc1d33a57b2228b09fb735dd7f015baab1304177ebd1ee9c41cb07e2d312328867be189199cc929a3e4ae3cb4ac63b0d0b1741fff55c3c64f61b4919159048be7c4f45238df2ead3b6c8ddeadfe103d14f76c22546532f71cd9ce0c4ca0845b7aae47115ff9f2689736236e26f04a36d4be8d258226b40c3e594beb87ff2cf674fe5c790dc1f9fe5aa1bded8ec8578fd151cee0e6956c630f6ce76be57965a8e4e59b5b8bb94053398619cee54bad207b26a7985a69cf06a43660fbbff22b82a07b837430624208753a9d455ca164257f5bc3f067f12fdff1d3d7ebfd33df692ecae4257137f3b8ff4642c068530851f74c97e4bcb9a0bfaaac4946a63de3fded919292ce9434047a78b0f6e41416958a6a5a02ac108049557b196d6e53d09b5ad13430f443b7476105afdd0241f1323ab7e3e8790b08fa708bd109b62acc5d9a7f6650617943191c88f344b8f43a0676ee1f17fd42a81fe2a2d84ed5b36366f7f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(144196);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2020-3429");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr69019");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wpa-dos-cXshjerc");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family WPA Denial of Service (cisco-sa-wpa-dos-cXshjerc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a Denial of Service vulnerability in the WPA2 and WPA3
security implementation of Cisco IOS XE Wireless Controller Software for the Cisco Catalyst 9000 Family and could allow
an unauthenticated, adjacent attacker to cause denial of service (DoS) condition on an affected device. The
vulnerability is due to incorrect packet processing during the WPA2 and WPA3 authentication handshake when configured
for dot1x or pre-shared key (PSK) authentication key management (AKM) with 802.11r BSS Fast Transition (FT) enabled.
An attacker could exploit this vulnerability by sending a crafted authentication packet to an affected device. A
successful exploit could cause an affected device to reload, resulting in a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wpa-dos-cXshjerc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50813faf");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr69019");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr69019");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3429");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects Cisco Catalyst 9300, 9400, 9500, 9800
if ('cat' >!< tolower(device_model) || (model !~ '9[3458][0-9][0-9]'))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['dot1x_psk_akm_ft_enabled'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr69019'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
