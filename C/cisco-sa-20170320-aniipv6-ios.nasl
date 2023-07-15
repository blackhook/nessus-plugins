#TRUSTED 0ee99a3c26a19fb91290623ffa25e07f109f6c834f7c4ed9fb4dfe56b7877b640faba0c279ca3937fce68fc25f62d3bbe772d9e07a7a1bc15d300edabe7be970fc975d9d5abc4ea84b227d4e0bc76049df287d63cb4bef57eea6f7994020bca14e93846b1ac8ffa24443839a62646be4af88e9dc7755b05fdb6a0216c54b624d7d067d473997ba621d477694814732f0529e2fcc62691c0c986d562725eed73616aa80ea199a0f9b12c272459ad54b1784627182a8b0bfec19e5846fda180e0a6e8fa244b998d3203241548447053696ed43cfc1693f4b473f01d2bf2f9753e2ee7f8e691f5305d1862dea7fd790190f352e034407d08b47b66708ae0f99132bf675a6310728bad050a9bda0ded73b512dec3b9238fd34786a6f84a14ce7e0e47aa6449b94379b74bfe308a7f9c3ef9fb0bebba8a6547dfeb2724e8f568e319a1a1d874e8b45b26a413880e369d93e1dffd2d4223c050598285cb14ac23e1abbf707056adf97122c6441cae8dfce3147ac473ecdd340d8a7c4d1e981616bcc5a7f9e8afa35865afebe75b01662b6bcea56fbf522b18c049aaae89f049a13e540b856f23c0e3b13b211c56d2eca02f6091b525ffe05463e7c193a5dbc6dcf0b7ca3f7c88cf316296255740f690c5cadd92d5deafd9071abd738d34f613726e3231383b4464e171d71535e8faaffd1109266f9a04c19fe229d89765e562afc6125
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97945);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2017-3850");
  script_bugtraq_id(96971);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc42729");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170320-aniipv6");

  script_name(english:"Cisco IOS ANI IPv6 Packets DoS (cisco-sa-20170320-aniipv6)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Autonomic Networking Infrastructure (ANI) component due to
incomplete input validation of certain crafted IPv6 packets. An
unauthenticated, remote attacker can exploit this issue, via specially
crafted IPv6 packets, to cause the device to reload.

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

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS");

version_list = make_list(
  '15.3(3)S',
  '15.3(3)S1',
  '15.3(3)S2',
  '15.3(3)S3',
  '15.3(3)S6',
  '15.3(3)S4',
  '15.3(3)S5',
  '15.2(3)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(5)E',
  '15.2(5b)E',
  '15.4(1)S',
  '15.4(3)S',
  '15.4(1)S1',
  '15.4(1)S2',
  '15.4(2)S1',
  '15.4(1)S3',
  '15.4(3)S1',
  '15.4(2)S2',
  '15.4(3)S2',
  '15.4(3)S3',
  '15.4(1)S4',
  '15.4(2)S3',
  '15.4(2)S4',
  '15.4(3)S4',
  '15.4(3)S5',
  '15.4(3)S6',
  '15.5(1)S',
  '15.5(2)S',
  '15.5(1)S1',
  '15.5(3)S',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(2)S3',
  '15.5(3)S2',
  '15.5(3)S0a',
  '15.5(3)S3',
  '15.5(1)S4',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T2',
  '15.6(2)SN',
  '15.6(3)M'
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
