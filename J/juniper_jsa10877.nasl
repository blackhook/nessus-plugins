#TRUSTED 472e4ced9aea89a8978662dc0c8c6a71ef5221d6fa62747edf4d8b8d79374f8cf1263c165d79a162501ae90c85c136fe5453674ebf23a730dc382ff57da97f40e08b59da5cb561a9ebf81bd80ea20a7602c9b04f448c553abd39750379790d097a49faffb36b5029194aa06108e21f4b96f68334b88171a1dca0fdab2210e6c0c128b4aafc8728b8a75da1da26b85818d55d2606aa221116a8f4d1410b3537ecee58ca6e082196b39d2a1d21060eaedffef2fe4e24e9b713e3be9bf03ac2375f42a54b267bf6a7387f11a2800ecf4103f6902dbe82db8685ce4262d855b9b8c525948796f1a197b50d5b1d6c12c2b09e433f5ff7c1ad787ab1cf53b777a0f359b377060d9346fd8fe250c4edf937a2969dfcc35b465d5dbe4975527e54fc27aba198d76020765a2d8f2349e57a51f7dc0e7c837bf6f5ced10c62db70f68a63841288516f21044f8ee997f17d0300b8f6044e951e361df31170c45ba1b596dbeef0ceb34a4534091075b810146b2531bc05a6bb3ed91bdaee0e7a681690d5f5914cd1675a508e9fb347299f132f2f45814ae0e7ea14e3d8c6b35789c2a72ac6e99cea482b6b3d7305ce9c614b4b3a54ef7f9ec63782b263f01ba9539f475da438ea9d82f688479eec7df8d11984dca3fa2514909aa19b8bd0f498b0e884250506abe24cea0fd204c38bfbf637f1bd50a29575bf0dee230d518f8249d30dc3179d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118231);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/08");

  script_cve_id("CVE-2018-0043");
  script_xref(name:"JSA", value:"JSA10877");

  script_name(english:"Juniper Junos RPD MPLS RCE (JSA10877)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a potential remote code execution vulnerability due to
how the routing protocol daemon handles MPLS packets. An attacker could
potentially crash the RDP service or execute code.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10877");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10877.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0043");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

fixes = make_array();
# 12.1X46 versions prior to 12.1X46-D77 on SRX Series
# 12.3X48 versions prior to 12.3X48-D75 on SRX Series
# 15.1X49 versions prior to 15.1X49-D140 on SRX Series
if (model =~ '^SRX')
{
  fixes['12.1X46'] = '12.1X46-D77';
  fixes['12.3X48'] = '12.3X48-D75';
  fixes['15.1X49'] = '15.1X49-D140';
}

# 14.1X53 versions prior to 14.1X53-D47 on QFX/EX Series
if (model =~ '^(QFX|EX)')
{
  fixes['14.1X53'] = '14.1X53-D47';

  # 15.1X53 versions prior to 15.1X53-D59 on EX2300/EX3400 Series
  if (model =~ '^EX(23|34)00')
    fixes['15.1X53'] = '15.1X53-D59';

  # 15.1X53 versions prior to 15.1X53-D67 on QFX10K Series
  if (model =~ '^QFX10K')
    fixes['15.1X53'] = '15.1X53-D67';

  # 15.1X53 versions prior to 15.1X53-D233 on QFX5200/QFX5110 Series
  if (model =~ '^QFX(5200|5110)')
    fixes['15.1X53'] = '15.1X53-D233';
}

# 15.1X53 versions prior to 15.1X53-D471 15.1X53-D490 on NFX Series
if (model =~ '^NFX')
  fixes['15.1X53'] = '15.1X53-D471';

# 14.1X53 versions prior to 14.1X53-D130 on QFabric Series
if (model =~ '^QFabric')
  fixes['14.1X53'] = '14.1X53-D130';

# 12.3 versions prior to 12.3R12-S10
fixes['12.3R'] = '12.3R12-S10';

# 15.1F6 versions prior to 15.1F6-S10
fixes['15.1F6'] = '15.1F6-S10';

# 15.1 versions prior to 15.1R4-S9 15.1R7
if (ver =~ "^15\.1R4($|[^0-9])") fixes['15.1R'] = '15.1R4-S9';
else                             fixes['15.1R'] = '15.1R7';

# 16.1 versions prior to 16.1R3-S8 16.1R4-S8 16.1R5-S4 16.1R6-S4 16.1R7
if (ver =~ "^16\.1R3($|[^0-9])")      fixes['16.1R'] = '16.1R3-S8';
else if (ver =~ "^16\.1R4($|[^0-9])") fixes['16.1R'] = '16.1R4-S8';
else if (ver =~ "^16\.1R5($|[^0-9])") fixes['16.1R'] = '16.1R5-S4';
else if (ver =~ "^16\.1R6($|[^0-9])") fixes['16.1R'] = '16.1R6-S4';
else                                  fixes['16.1R'] = '16.1R7';

# 16.1X65 versions prior to 16.1X65-D48
fixes['16.1X65'] = '16.1X65-D48';

# 16.2 versions prior to 16.2R1-S6 16.2R3
if (ver =~ "^16\.2R1($|[^0-9])") fixes['16.2R'] = '16.2R1-S6';
else                             fixes['16.2R'] = '16.2R3';

# 17.1 versions prior to 17.1R1-S7 17.1R2-S6 17.1R3
if (ver =~ "^17\.1R1($|[^0-9])")      fixes['17.1R'] = '17.1R1-S7';
else if (ver =~ "^17\.1R2($|[^0-9])") fixes['17.1R'] = '17.1R2-S6';
else                                  fixes['17.1R'] = '17.1R3';

# 7.2 versions prior to 17.2R1-S6 17.2R2-S3 17.2R3
if (ver =~ "^17\.2R1($|[^0-9])")      fixes['17.2R'] = '17.2R1-S6';
else if (ver =~ "^17\.2R2($|[^0-9])") fixes['17.2R'] = '17.2R2-S3';
else                                  fixes['17.2R'] = '17.2R3';

# 17.2X75 versions prior to 17.2X75-D100 17.2X75-D42 17.2X75-D91
fixes['17.2X75'] = '17.2X75-D42';

# 17.3 versions prior to 17.3R1-S4 17.3R2-S2 17.3R3
if (ver =~ "^17\.3R1($|[^0-9])")      fixes['17.3R'] = '17.3R1-S4';
else if (ver =~ "^17\.3R2($|[^0-9])") fixes['17.3R'] = '17.3R2-S2';
else                                  fixes['17.3R'] = '17.3R3';

# 17.4 versions prior to 17.4R1-S3 17.4R2
if (ver =~ "^17\.4R1($|[^0-9])") fixes['17.4R'] = '17.4R1-S3';
else                             fixes['17.4R'] = '17.4R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# MPLS must be configured to be vulnerable
override = TRUE;
buf = junos_command_kb_item(cmd:"show mpls interface");
if (buf)
{
  override = FALSE;
  if ("MPLS not configured" >< buf)
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have MPLS enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
