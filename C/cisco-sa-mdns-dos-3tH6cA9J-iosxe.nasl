#TRUSTED 79e399e7b5b5a565a6ea29a9bf83d6c0f12e74a04a7cb11e3e1051c4254f86aa762946b05bed5cf0ab854072b4fdce75dd819d438c7040f32863479c15758b592eeb12c948734abceb15186e17c80e39880fc77e340d51302ba298b521ff6e9382fbf350ab49fd88de1c56c839ae04467e0f6c6ef91d9a26d3c5726b2f4682e8925d6f7c7ccb5188d0ceb5b6bff97b7be69c77354feca28c0f70d82578b2227eaf4fe13b6a138598ddfdad484ea4f9edb110580b909e2b7aed3d630ceada954cff6fcfe0937c3688a649f8086513ca2c2699d41e3f3517df24d36b3c830eac93e8d75da4ca0fc278ed175dd50bd27d04610b296cf47054d1f9892d79e35ea90de232f2eec2b42c6d818ec4ac075550d25f056860598aff6f1a87558585776a76d8c8549590b24f0980b0b074145ee9a16b8886c5e0536183def08ce4b70c72a62a4c2e5bebe1019bbf368712fb74445cb4c0b8891cf974a0e4e34f45f40cb098072c67b757dcca5b0e005439e7c9d9a4296294af1a32308aadcab86951c532b3c35becc10bd6f57aadb13f13008b241b15993b20c7fa83565f55647b782f4e264a759a2d05b95d9dfe12ea51ab8e8e870161435b40c12596ff966587d61813dbf83e9d1ffbcca0c7562622adf08e30a08bcd2e91c8527248e6c1d0079a17368e7b9191b97b911ab67cb22f8e215ab3889da928ceb4b2e6202744955cad0aa812
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141461);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/07");

  script_cve_id("CVE-2020-3359");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr57654");
  script_xref(name:"CISCO-SA", value:"cisco-sa-mdns-dos-3tH6cA9J");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software for Catalyst 9800 Series Wireless Controllers Multicast DNS DoS (cisco-sa-mdns-dos-3tH6cA9J)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco IOS XE Software for Cisco Catalyst 9800 Series Wireless Controllers
due to improper validation of mDNS packets. An unauthenticated, remote attacker can exploit this issue, via a crafted mDNS
packet to an affected device, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-mdns-dos-3tH6cA9J
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c17f0e7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr57654");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3359");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/device_model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

if (toupper(product_info['model']) =~ "^(C)?9800")
{
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
    '17.2.1t',
    '17.2.1v'
  );

  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['mdns'];

  reporting = make_array(
    'port'     , product_info['port'], 
    'severity' , SECURITY_HOLE,
    'version'  , product_info['version'],
    'bug_id'   , 'CSCvr57654',
    'cmds'     , ['show mdns summary']
  );

  cisco::check_and_report(
    product_info:product_info,
    reporting:reporting,
    vuln_versions:version_list,
    workarounds:workarounds,
    workaround_params:workaround_params
  );
}
else
{
  audit(AUDIT_DEVICE_NOT_VULN, product_info['model']);
}