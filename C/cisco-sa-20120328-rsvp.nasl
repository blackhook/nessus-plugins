#TRUSTED 861878d1a712fdc3fc359ecb134bb2bba535a6ac52023d30a0255f3424a7b3b9bbf1b7a4adb6cea10e17402a1f363d4525bd39fa0c682c3423654fa0259e645a65d573a54154c17d314b6d896bd5518e4cd7a335b3644a49e6409a7b89d419e400e693060f99ffc313f26a0b04005a8b45a3ccbeeff60c3e07cdad63f7012bedc177150a771701b54221757535e7eccffd7975236951971ef52308ed3e5b0a18617a760cc534772402182c867aecc5e306b1b46916447f757a58385cd23566fcfe2784e47b4e61a0e92dee57c0566ffe61cc2661373a518cf211a483205dece649e07cefe60c99574b654268e0bfef176033c9b00eb21af25ef07acfe3369eb4c7e8878f38c826ad5ebe7f87875d85a736bb6eb64e1d773dd43eed0c8924f79fbdd3a4206abccb6fb789d4c62f24a5891d5ef171c56e0da742ce021ef01a7e4cc9a5a951a45f64f140fc84911c4175f4a38152fdd2f64cb24783364b650016bd5bca186ff0b953a6aff727525e81e99f9eb66aa5cc2c741d204b42b7b4db45b1bf8d06ce78ba7cfdb538fa4d99e3786567cfe3c6b559f3a34e2b2a773e48753881a9b1fa6878f3215a738d360aa000bf75be41797180ee7e1a632bb7b429d3aef20301506afd38b75ca79ebdbf05119cad2f46983acb98da41f9db568396e2be56c5b989422e446b5f7baf8e2eb89e711119ba634d825582d733b40d8bc068fd
#TRUST-RSA-SHA256 0a295139a69f2ca05f5dba67d280ff08bf1c0674de690c6b0346bea15d9133d51a4a87af0f033181f06164d0c63f797cfc957edcc95a7f5ce0d98a34c12384783cbbb0be71a150bdc4dcf3d307d9e5c65eec76ae9045584f0875a70fbb57901a275dbfcf34bda7ad458c506ae53d005d4132d0c7fc668e63dfcbc83b176cfd75c4e6e4881e602a155bd53651405446bffeefac47a703376b860d3cfc4c8393d5303994ccbc6728cc510464b7cbe4b4986a752ce5a2a9a8d08090d5f6e2bd96dbe50a0f249720c46f5399fd635de1992397d93b8d6e7b7892aa062fe1b880047e6e7c428cc7bf3aee63229491da2375fb9ccb7659ed2e3e4af3048b1d92c2764560dafefe17bbe173ff45f30f57248b300d7771d3dca04c4ab0ba521598994048761e6c878dad6d1375f118ee9aa1fbbe276134ed434549350739601f1893ab41025ec2ce86c83769c582040d7b8b153bbc6f1fd07cd74011465de4718e3a7517f1fc5e7bc806eb25f85ec09dd5f5a81252e1d98c34dff8de7a954386b6363f3f8c2a233f1a7377e70f328609d2576c7644944188574e204cea449b2c5aae91db88fd9a3a602294feb80b4b7a05a9b797c6cd0f78491ae4364acef4d93ec24fef3b553d3e2463425efa8cd7034fe59255a38a5ae67a37ad1c733689640a2e6f3cd58e50406f57dfd6594a6bd9e15d48edd288e46369d25894fefde110b9a92f79
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120328-rsvp.
# The text itself is copyright (C) Cisco
#

include('compat.inc');

if (description)
{
  script_id(58571);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_cve_id("CVE-2012-1311");
  script_bugtraq_id(52754);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts80643");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120328-rsvp");

  script_name(english:"Cisco IOS Software RSVP Denial of Service Vulnerability (cisco-sa-20120328-rsvp)");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS Software and Cisco IOS XE Software contain a vulnerability in the RSVP feature when used on a device
configured with VPN routing and forwarding (VRF) instances. An unauthenticated, remote attacker can exploit this to
cause an interface wedge, which can lead to loss of connectivity, loss of routing protocol adjacency, and other denial
of service (DoS) conditions. This vulnerability could be exploited repeatedly to cause an extended DoS condition. A
workaround is available to mitigate this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120328-rsvp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?685daaab");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCts80643.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1311");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('ccf.inc');
include('audit.inc');
include('lists.inc');
include('cisco_kb_cmd_func.inc');
include('cisco_func.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

product_info = cisco::get_product_info(name:'Cisco IOS');

vuln_versions = [
  '15.0(1)M1',
  '15.0(1)M5',
  '15.0(1)M4',
  '15.0(1)M3',
  '15.0(1)M2',
  '15.0(1)M6',
  '15.0(1)M',
  '15.0(1)M7',
  '15.0(1)M6a',
  '15.0(1)XA2',
  '15.0(1)XA4',
  '15.0(1)XA1',
  '15.0(1)XA3',
  '15.0(1)XA',
  '15.0(1)XA5',
  '15.1(2)T',
  '15.1(1)T4',
  '15.1(3)T2',
  '15.1(1)T1',
  '15.1(2)T0a',
  '15.1(1)T3',
  '15.1(2)T3',
  '15.1(2)T4',
  '15.1(1)T2',
  '15.1(3)T',
  '15.1(2)T2a',
  '15.1(3)T1',
  '15.1(1)T',
  '15.1(2)T2',
  '15.1(2)T1',
  '15.1(1)XB',
  '15.1(1)XB3',
  '15.1(1)XB1',
  '15.1(1)XB2',
  '15.1(4)XB4',
  '15.1(4)XB5',
  '15.1(4)XB6',
  '15.1(4)XB5a',
  '15.1(2)S',
  '15.1(1)S',
  '15.1(1)S1',
  '15.1(3)S',
  '15.1(1)S2',
  '15.1(2)S1',
  '15.1(2)S2',
  '15.1(3)S1',
  '15.1(3)S0a',
  '15.1(4)M',
  '15.1(4)M1',
  '15.1(4)M2',
  '15.1(4)M0a',
  '15.1(4)M0b',
  '15.1(2)GC',
  '15.1(2)GC1',
  '15.0(1)SY',
  '15.1(3)SVG',
  '15.1(3)SVG2',
  '15.1(3)SVG3',
  '15.1(3)SVG1b',
  '15.1(3)SVG1c',
  '15.1(3)SVG3a',
  '15.1(3)SVG3b',
  '15.1(3)SVG3c',
  '15.1(3)SVG2a',
  '15.1(3)SVG1a',
  '15.1(3)SVH',
  '15.1(3)SVH2',
  '15.1(3)SVH4',
  '15.1(3)SVH4a',
  '15.1(3)SVI2',
  '15.1(3)SVI1a',
  '15.1(3)SVI2a',
  '15.1(3)SVI3',
  '15.1(3)SVI31a',
  '15.1(3)SVI31b',
  '15.1(3)SVI3b',
  '15.1(3)SVI3c',
  '15.6(2)SP3b',
  '15.1(3)SVJ',
  '15.1(3)SVJ2',
  '15.1(3)SVM3a',
  '15.1(3)SVO4a',
  '15.1(3)SVR'
];

flag = FALSE;
for (var potential_ver of vuln_versions)
  if (product_info['version'] == potential_ver)
   {
    flag = TRUE;
    break;
   }

if (!flag)
  audit(AUDIT_HOST_NOT, "affected");

override = 0;
# Not using cisco_workarounds.inc because it's not likely to be reused and adding lists.inc to that file would add a
# lot of overhead to many plugins.

# Determine whether devices are configured to use RSVP
buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");

if (check_cisco_result(buf))
{
  if (!preg(multiline:TRUE, pattern:"(ip rsvp bandwidth|mpls traffic-eng tunnel)", string:buf))
    audit(AUDIT_HOST_NOT, "affected because RSVP is not configured");
}
else if (cisco_needs_enable(buf))
  override = 1;

# Determine whether (and which interfaces) RSVP is active on a device
buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_rsvp_interface", "show ip rsvp interface");

if (check_cisco_result(buf))
{
  lines = split(buf);
  if (max_index(lines) <= 1)
    audit(AUDIT_HOST_NOT, "affected because RSVP is not enabled");

  rsvp_interfaces = make_list();

  first = TRUE;
  for (var line of lines)
  {
    res = pregmatch(pattern:"^\s*(\S+)", string:line);
    if (empty_or_null(res)) continue;

    interface = res[1];
    if (first)
      first = FALSE;
    else
      collib::push(interface, list:rsvp_interfaces);
  }
}
else if (cisco_needs_enable(buf))
  override = 1;

# Determine whether (and which interfaces) VRF is configured on a device
# Multiple interfaces will be separated by two spaces. Mutiple protocols are separated by a comma and no space.
# According to: 
# https://www.cisco.com/c/en/us/td/docs/ios/mpls/configuration/guide/12_2sr/mp_12_2sr_book/mp_vpn_ipv4_ipv6.html
buf = cisco_command_kb_item("Host/Cisco/Config/show_vrf", "show vrf");

if (check_cisco_result(buf))
{
  lines = split(buf);
  if (max_index(lines) <= 1)
    audit(AUDIT_HOST_NOT, "affected because there are no interfaces with VRF enabled");

  vrfs = make_array();

  first = TRUE;
  for (var line of lines)
  {
    if (first)
    {
      first = FALSE;
      continue;
    }
    res = pregmatch(pattern:"\s*(\S+)\s+\S+\s+\S+\s+(\S.*)\s*$", string:line);
    if (empty_or_null(res)) continue;
    vrf_name = res[1];
    var vrf_ifaces = make_list();

    interfaces = res[2];
    interface_list = split(interfaces, sep:"  ", keep:FALSE);
    for (iface of interface_list)
      collib::push(iface, list:vrf_ifaces);

    # save the list of interfaces after all our pushing is done
    vrfs[vrf_name] = vrf_ifaces;
  }
}
else if (cisco_needs_enable(buf))
  override = 1;

# Ensure there's at least one VRF configured without RSVP on any interface
vrf_without_rsvp = FALSE;
foreach (key in keys(vrfs))
{
  diff = collib::subtract(vrfs[key], rsvp_interfaces);
  if (max_index(vrfs[key]) == max_index(diff))
  {
    vrf_without_rsvp = TRUE;
    break;
  }
}

if (!vrf_without_rsvp)
    audit(AUDIT_HOST_NOT, "affected because there are no VRF configured without RSVP");


report =
  '\n  Cisco bug ID      : CSCts80643' +
  '\n  Installed release : ' + product_info['version'] +
  '\nA vulnerable configuration was discovered by using the following command(s):' +
  '\n - show running-config' +
  '\n - show ip rsvp interface' +
  '\n - show vrf' +
  cisco_caveat(override) +
  '\n';
security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
