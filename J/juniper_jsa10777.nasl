#TRUSTED 79b2d73ebaf4b4a864830d582c9d9ff8e8ea1a23c1f9f4d2c048a7be952e88270c6a21d8badac2d1701afed151bb9cb96f1f1dfb86def864a20cff413b492000f83dba1e85f707521650067ea18a8ece4d8bfcbf80fc08da56be8683dfef233e4f13a24d724cb5cb87e6e262c3a39908bafdbd963abb30b0de48b751ef0f08569428d36d28cc8b3a2d86ae58e483ca500001b97b81d64b9a8926109baee17080402feaa4228eb059805061711bbde2d15650ec5e38aed4653448743d5256f324a4ab655023f76f684d1983cb843a5da24f632e6d19f397bf01593cff5ae28b495ba75e38b0f267d32cea37ae601776e85595511a54aa352c4bd389f74495c1b7576cee852dfd0a44a4d3c721aacf15b3b35f1fc61129a752ff57c055e6f96eca3422da156f8bed5f5205bb7507f42af06460fbcb12ed187dd4ba956623846962da3baf0d9551550bdb571175096c9492ed3c60019b30d616083d4d0b0fad0f3a54539d144a7976afcce9aa259f93d1e664d0a3412a08edb6f55cc4b7b63da49ae707f5468e580d0beb29df859220ec9216a34fb762bb00b06de5415eaaf4225fa5dc819190007e6913f5f33ababc5ca114bce55bcbb0759d6bc22473525b2c57467ac8bd4a1284b3a1d365528240ed9de0615a2345684a4e6b4236f96b517ebb7cf39931682d18538063f082420dbfa7cdcba1b040da165abfb9b518eb9bb22c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99524);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2312");
  script_bugtraq_id(97611);
  script_xref(name:"JSA", value:"JSA10777");

  script_name(english:"Juniper Junos Routing Protocol Daemon LDP Packet DoS (JSA10777)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the remote
Juniper Junos device is affected by a memory leak issue in the routing
protocol daemon (rpd) when handling a specific LDP packet, which over
time will consume memory that cannot be freed without restarting the
rpd process. An authenticated, adjacent attacker can exploit this, by
repeatedly using this kind of packet, to cause the rpd process to
crash and reload, resulting in a denial of service condition. Note
that this issue affects devices with either IPv4 or IPv6 LDP enabled
via the '[protocols ldp]' configuration. Furthermore, the interface on
which the packet arrives needs to have LDP enabled.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and current configuration.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10777&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fa1895d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10777.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
# Workaround is available
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array();

fixes['13.3'] = '13.3R10';
fixes['14.1'] = '14.1R8';
fixes['14.2R7'] = '14.2R7-S6';
fixes['14.2'] = '14.2R8';
fixes['15.1F2'] = '15.1F2-S14';
fixes['15.1F6'] = '15.1F6-S4';
fixes['15.1F'] = '15.1F7';
fixes['15.1R4'] = '15.1R4-S7';
fixes['15.1R'] = '15.1R5';
fixes['15.1X49'] = '15.1X49-D70';
fixes['15.1X53'] = '15.1X53-D63'; # or 15.1X53-D70 or 15.1X53-D230
fixes['16.1'] = '16.1R2';
fixes['16.2'] = '16.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show ldp statistics");
if (buf)
{
  if (preg(string:buf, pattern:"LDP.* instance is not running", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because LDP is not enabled"); 
  else
    override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
