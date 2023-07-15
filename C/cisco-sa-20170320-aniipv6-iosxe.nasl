#TRUSTED 93611b3f46ebd3360167b7fac1a41b44ec2f8851aa6123267514abcf360e47be42dc0dd6044edbdbb88a4e527e8ffa8293a46fa82ce2f61f3a3534179d3ec95741e39eb222a941f16031d9969807aad7609ef3c458ee5e266909e73676298a9c412a5cfe8ab1bca6d077915449034f42708d1f24770ec27aa5d5aa08ece4aa60d89c44c4b9bd40081f429be5fd064336daf0a81bbb75702e7357a028981e487520bc62320c9aa5244e047f53d2ef74faf125ddad39abd4877253b2c7f7759afa5b5dfe4a9bc3c1905a2adbbfff911eacc0f8d986d6202013a70b7f937a65d3051c6cd13fa6fbb8fa9c3c145447796f1072dd80aece810426558eb37ec3f2808c5151e8fc3cd2cfc79e7d06658ea351908ca28b2d3ce1554a7ddab7ececd03201ac5089b525172a2e3d08783e7f13f23870aed8fdd78581a036e2fe083fad43a4fec5b8d8c365efbcd932376d8ddadf365577fd9b17ffeda4abafeeaecf2212778bddb5d9487ba3574571db613c90d1f185e178cb280271bcaf135a3bf5f8f046101ddd3685917ca5a3e0e326e6983bbf3002933f5dc9f1da52ea6f2e223152ca513c99049c3bdbd5e94bf86ef4d3ceaf0969ff79cab90380655f4b8ccbd49a151c2ca2648e89f10f86d2c399d1d1e07824dafaacd997a5f85a4153ee606bb67d0409f86ddb6c3277a97ab5c7687adb152e07ffe65b2ef7abfaeefb2eadf25d3a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97946);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2017-3850");
  script_bugtraq_id(96971);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc42729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170320-aniipv6");

  script_name(english:"Cisco IOS XE ANI IPv6 Packets DoS (cisco-sa-20170320-aniipv6)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Autonomic Networking Infrastructure (ANI)
component due to incomplete input validation of certain crafted IPv6
packets. An unauthenticated, remote attacker can exploit this issue,
via specially crafted IPv6 packets, to cause the device to reload.

Note that this issue only affect devices with ANI enabled that have a
reachable IPv6 interface.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-aniipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d249229");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20170320-aniipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.1xbS',
  '3.10.8S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.16.0S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.5S',
  '3.16.4dS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.3S',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3vS',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.9.0E',
  '3.9.1E'
  );

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ipv6_enabled'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvc42729",
  'cmds'     , make_list("show running-config")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
