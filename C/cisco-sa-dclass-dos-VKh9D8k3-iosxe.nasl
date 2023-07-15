#TRUSTED 55ec02f63a88a9cc8198c7b7b3929b696474eff1374ecd38d54b3d0c13ad07d8f9729f822f0e5d3cb891078a13479bb97c9b6211cf4f57ea12fa9057f3a399b6bc19151a8422b0867b8db1033c8dbe1842995650ef0edd1b7e14cd6c07adf0c6e781dfe5368a213a24753fb6be76974105803bea529100bc2197897e20f136dd08c0571a7ec7e1505c52bfb83c74f13602fd071612ac12a32dd4ecbbed5c1f8290fe0325a6aee3d34c770cb104cbcfda18b04c807fa1c0047f9e9c6446a75376ae6c15cbf9d08ac2024dab1002caa1ea1bd4bb46eeff987e57ed8ba271a6dd9254849afbd7040dfa7a8546c82a8feb674067334333a3a2e5c38d0bbaf869d3f4a35f14fa7a351bd19a1c0f035ec5d3de90e0f04bcebc4b4bae52e1583cc7831098a4c67a22d4d5a281557510ab774d1da4fd5717c277486518012fb20a133521d9866de15a4a0db9f69100d76394dd804c0e3efef305cc6056bae119ecd5587381692868db587ea1e539e7358c1b93cab032eb5ab47834108893f9cfdcf36ac94e0cfeb5c96d021cc6cb09a0ae3bce613b0fd1c511ecd7e4562946fe815aac64780241a8e4165a22c7537f2ebc72b2d6df75502f7e19193b6db351ad9e4b72141737a3210d9a862a9b7f3c01fcdb9886485676731ddf2ccc48d9db39346b134d856133183a25c5e6aea6df796cb9b77ee579e78c821995776a60b903423a9af0
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144503);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3428");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96076");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dclass-dos-VKh9D8k3");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Wireless Controller for the Catalyst 9000 Family WLAN Local Profiling DoS (cisco-sa-dclass-dos-VKh9D8k3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE is affected by a Denial of Service vulnerability in the WLAN
Local Profiling feature of Cisco IOS XE Wireless Controller Software for the Cisco Catalyst 9000 Family. This
vulnerability is due to incorrect parsing of HTTP packets while performing HTTP-based endpoint device
classifications. An unauthenticated, adjacent attacker could exploit this vulnerability by sending a crafted HTTP
packet to an affected device. A successful exploit could cause an affected device to reboot, resulting in a DoS
condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dclass-dos-VKh9D8k3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53ee1c87");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr96076");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3428");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Host/Cisco/device_model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects Cisco Catalyst 9300, 9400, 9500, 9800
if ('cat' >!< tolower(device_model) || (model !~ '9[3458][0-9][0-9]([^0-9]|$)'))
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

workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
workaround_params = {'pat':make_list('device classifier', 'http-tlv-caching'), 'require_all_patterns':TRUE};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr96076'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
