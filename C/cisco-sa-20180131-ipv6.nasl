#TRUSTED 9bd5742dfa95d0cfffddf87b4585d3572ec4260832f6e42e251d7026e888a336b7dc83ade2be41e9be47d41e7f117a1f5271f8d5ca9b26f1bd3c7d5699be18ca47a65da1c86139d89e3c29936d9f43068d955a8c0aec7041ea1ea68d2c866aebf5c9af35844f8cd46c97d0c6e35cb549f35781212893cf0878b127d51cc82b4f84274e97ab34f94ccec4d86ea46103996004fbde0d4308d35883b4346c89ca5fc0e26b59ff44697bbf54b1c23449e5147a00870f73bfcf6d485ca7cacd3d45b0330ed1218c8b780168e46225c8ce1ff2b9b1d622ecc54c9465ae7f5032478f3a3233aa1ec2fd017f9af8c06e1164b48ed1401a03d40ea0ccf17b54800a97bbbb0c1379c891cc1a312a028cd308f57ab31fba30098f5a96a286f11aa5dca04688234c9c49853bc4f983b4c321cf7ad69a94b7a2f022507cab19bc88151181c316b806df0f349b70dc42c4845ba8d9e262402a370682e04b5a73e4ab0be2dfe72017b89cbb8bf6f57b819e688c9b094bf222b1023109cbcee47ffbe3956ece05584256b5ffa17ee7446d37cc494929176da844f2c6cec00365c533d6a84aadf5942f9279ab10c539e532684d7eb48f4abc0348cf99e1cada84ff360202dae6fd7948f167a84b4047bed0a36b2791886321f2d899c23e48a261f9dd91b46a0f0abb7ec788ae9468851bc746f148b69001453ed07cc4ed6b1e855c992580c4215447
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133861);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2018-0136");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg46800");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180131-ipv6");

  script_name(english:"Cisco Aggregation Services Router 9000 Series IPv6 Fragment Header DoS (cisco-sa-20180131-ipv6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a denial of service (DoS) vulnerability
in the IPv6 subsystem due to incorrect handling of IPv6 packets with a fragment header extension. An unauthenticated,
remote attacker can exploit this, by sending IPv6 packets designed to trigger the issue either to or through the
Trident-based line card, in order to trigger a reload of Trident-based line cards and cause a denial of service. This
vulnerability affects only Cisco Aggregation Services Router (ASR) 9000 Series devices.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180131-ipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae7d2a6f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg46800");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvg46800.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

if (cisco::cisco_is_switch())
  audit(AUDIT_HOST_NOT, "an affected Cisco router");

model = toupper(get_kb_item('CISCO/model'));
if (empty_or_null(model))
  model = product_info['model'];

if ('ASR9' >!< model)
  audit(AUDIT_HOST_NOT, 'an affected model');

version_list = make_list('5.3.4');

vuln_line_cards = make_list(
  "^\s*PID:\s+A9K-40GE-L",
  "^\s*PID:\s+A9K-40GE-B",
  "^\s*PID:\s+A9K-40GE-E",
  "^\s*PID:\s+A9K-4T-L",
  "^\s*PID:\s+A9K-4T-B",
  "^\s*PID:\s+A9K-4T-E",
  "^\s*PID:\s+A9K-8T/4-L",
  "^\s*PID:\s+A9K-8T/4-B",
  "^\s*PID:\s+A9K-8T/4-E",
  "^\s*PID:\s+A9K-2T20GE-L",
  "^\s*PID:\s+A9K-2T20GE-B",
  "^\s*PID:\s+A9K-2T20GE-E",
  "^\s*PID:\s+A9K-8T-L",
  "^\s*PID:\s+A9K-8T-B",
  "^\s*PID:\s+A9K-8T-E",
  "^\s*PID:\s+A9K-16/8T-B"
);

smus['5.3.4'] = make_list('CSCvg46800', 'asr9k-px.5.3.4.sp7');

workarounds = make_list(CISCO_WORKAROUNDS['ios_xr_line_cards'], CISCO_WORKAROUNDS['ios_xr_ipv6']);
workaround_params = make_array('vuln_line_cards', vuln_line_cards);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg46800',
  'cmds'     , make_list('show diag', 'show ipv6 interface brief', 'show ipv6 vrf all interface')
);
cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  smus:smus,
  require_all_workarounds:TRUE
);
