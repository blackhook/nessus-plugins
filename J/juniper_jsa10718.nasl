#TRUSTED 6db75db08006fa18ca9e29e181dd1e287efc39692422a6444335a1b6f2503d01d010b02f1e1e7a2561e44dcac984a386406435bc463810893a8415a4efa60eb5ca2a03e9a523a3a800cda1fff4ef2482745aaf947056e032c1f6c217ea0f679f62b2fee2b60aa90d2b878a25148150f89d80c008237d9b37de47e6683dfdd8f99a12f485b89e086fc334974adc38f1e87395ec8793786d6461134dfa6ea95e6870522bd69a1e1f2c639609392b60729eb6989ee01eec8af228b9e2b758a90778f32d527c7ec85af0c163e42f8f472300ef7d8e358baf0a97599b023404590b960ae6b8ed69433fc26e80068e2ee27afff3dc141cf8cb9e8b9ee01e714b3353bfb9ccbd4433a90a0895d907426305a7b98e64b6da5e45705f9b521bbdb4a7c39f7925ac5302167eee3b019eeb69ec1671c1461493d1e055d2608c5a6e851ba19129df94c2ca3ffb934b00a7e310ef513335a50c0040e4c9e79665bd9b849e271b11f83aadd881c64923502c0008ebf973de25ecf4046d7e03f5bca1966bef8bddc56227e4fc746a2e17af05597273237f8281b670a85943a170baec2c8223df59dba54885b34d6acd1d4df5cdc0a63a7e171a924e01db5c595193408bda25cc881a0148aa81fde759095aac823acbfb5427e27e392abddf1e22f14cf3d68f5d9f0e9e92f032fe56e6962d6e78b269f8064265d4ce31a1abdb5d8e33c368aebec6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88093);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/04/11");

  script_cve_id("CVE-2015-5477");
  script_bugtraq_id(76092);
  script_xref(name:"JSA", value:"JSA10718");
  script_xref(name:"EDB-ID", value:"37721");
  script_xref(name:"EDB-ID", value:"37723");

  script_name(english:"Juniper Junos TKEY Query Handling DoS (JSA10718)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
a flaw in ISC BIND when handling queries for TKEY records. An
unauthenticated, remote attacker can exploit this, via crafted TKEY
queries, to cause an REQUIRE assertion failure and daemon exit.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10718");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10718.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X44'] = '12.1X44-D55';
fixes['12.1X46'] = '12.1X46-D40'; # or 12.1X46-D45
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3'   ] = '12.3R11'; # or 12.3R12
fixes['12.3X48'] = '12.3X48-D20';
fixes['12.3X50'] = '12.3X50-D50';
fixes['13.2'   ] = '13.2R9';
fixes['13.2X51'] = '13.2X51-D40';
fixes['13.3'   ] = '13.3R8';
fixes['14.1'   ] = '14.1R6'; # or 14.1R7
fixes['14.1X53'] = '14.1X53-D30';
fixes['14.2'   ] = '14.2R5';
fixes['15.1R'  ] = '15.1R5'; # or 15.1R3
fixes['15.1F'  ] = '15.1F3';
fixes['15.1X49'] = '15.1X49-D30';
fixes['15.1X53'] = '15.1X53-D20';
fixes['15.2R'  ] = '15.2R1';

check_model(model:model, flags:J_SERIES | SRX_SERIES, exit_on_fail:TRUE);

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "15.1R5")
  fix += " or 15.1R3";
if (fix == "14.1R6")
  fix += " or 14.1R7";
if (fix == "12.3R11")
  fix += " or 12.3R12";
if (fix == "12.1X46-D40")
  fix += " or 12.1X46-D45";

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services dns dns-proxy";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because proxy-dns settings have not been configured');
  override = FALSE;
}


junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_HOLE);
