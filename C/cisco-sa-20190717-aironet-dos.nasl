#TRUSTED 6f841b8f786744d73b99598d70acc9fdeb2f25f2a0920faafa585177551c75fa993c4633285d364dafb3a743f0d105e0042f153be576e22c2a70718f7b28eaad63685c08f16396eecb6875bed195f2ed6a6d772405299f60a5a8212f7585e6bd7372f916bbdb28020239ab3c96c85819025eb056a51bcfea70e9be5d850246de46cfc27a12098472cc0b3d47b300269d68e472efd857c6164ca1b076c8f4b3675bb693a16e0b406b03f69e9906dd766b22d22e18fa9a6d5182a3e35d9229234deae46c5e0c73b64c17bd6219c5066e6041727377985c1f412d5f6bedd458f85f29f4901a187a24e5491bd44329a46ced2ff8e4485dae027c27be4484307d2e34a48632f36209852ea65bb5e86a516458e75f5414205f7002d23dc6e0e125ac2e7e2904da9d0529d5f48a251c21566b74a77370cdcba608bc646a1ae4a30644fe72cee0b92e7edece6eb54d63792a0e1552217dd3288de1161ce6ab352a1ca1cb3739478a13b1b6b0bf2afbbf9aa192c32631714c13fa5f61dd038c55413d7b25af853f70ec07212e76a1e6a0d0ebad51fcd36e7e3c19a6a6b1fe7a87588085c08665413dda2a143dc55547d050f0902e2f83a26e086da13bd43137053930ab4b996a30e3c61f1647d743a4dee8abc59e91f4d099dac357fabde8f987924eba3c351e52b73db03f23465fd7bb4350d47a798f995e8f3d7d9c14afbd6d0c00ea45
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(143157);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2019-1920");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg95745");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190717-aironet-dos");

  script_name(english:"Cisco IOS Access Points DoS (cisco-sa-20190717-aironet-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco IOS Access Points due to a lack of complete error handling
condition for client authentication requests sent to a targeted interface configured for FT. An unauthenticated,
adjacent attacker can exploit this issue, by sending crafted authentication request traffic to the targeted interface,
to cause the device to restart.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190717-aironet-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a71c0f50");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg95745");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvg957452.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1920");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:aironet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl", "cisco_aironet_webui_detect.nbin");
  script_require_keys("Cisco/Aironet/Version", "Host/Cisco/WLC/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

# By default we won't check for a workaround.
workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);

# check if ssh was succesful
local_checks_enabled = get_kb_item('Host/local_checks_enabled');

# If SSH was not the source of the detection then this check is paranoid.
# If it was the source then we can check for a workaround and proceed without paranoia.
if (local_checks_enabled)
{
  workarounds = make_list(CISCO_WORKAROUNDS['show_running-config']);
  workaround_params = {'pat' : 'wlan security ft'};
}
else
{
  if (report_paranoia < 2) audit(AUDIT_PARANOID);
}

# determine if remote web detection was used.
if (empty_or_null(local_checks_enabled)) product_info = cisco::get_product_info(name:"Cisco Aironet Series Router Firmware");
else product_info = cisco::get_product_info(name:"Cisco Wireless LAN Controller (WLC)");

vuln_ranges = [
  {'min_ver' : '8.0', 'fix_ver' : '8.2.170.0'},
  {'min_ver' : '8.3', 'fix_ver' : '8.3.150.0'},
  {'min_ver' : '8.4', 'fix_ver' : '8.5.131.0'},
  {'min_ver' : '8.6', 'fix_ver' : '8.8.100.0'}
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvg95745"
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
