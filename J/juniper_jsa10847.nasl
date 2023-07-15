#TRUSTED 5019abba4474f67c6bd90d81406f703907eacb527abab7b0e710ffb48e26d6acd95aa97fde03c3b9fade2372fd4c464f5f3a921a0bc0692b223d8c663eb1f8ef99ab31327c617d11fbe82cc1c2b098d45c12169a03cafa95c54a11026b6c234f907da773a32d81e48c125362e578dbb64a1887ed6e528174424c307b2f661d79765b2d5b58abecb68d7c39cb6c0cf7dadc2042a59058d513f18732ff3bfa4879e4cb534ffd2d3ea80a49f9f1af8e6f0b3336797cab18f78924f6fb35b5e962ff86beca6fd7e4126866ed06f02f719f4ce3cf048122df2e041741be58abc027703627f4473b7545ed59adbf2caaed2e94b92d29680c518b2e7441969f73a4c6a1208b39c4ac957a24a69723ef10eec3062293b4b72e179125e2250aa76b32efa488b8a7801aec81f7b79268c818040057bfb4ebc7766d93d4e161f38e596f10a99395a05510a042dc2aedbb6a8c7c79bdb8791008c2cec3be8100cbc6cc8d2ecd8223b7f19cfad68d3298a1c98efbb2710dce070eae0e496ae4eeb4d2d1d0d3fafbbd090f29aacfa168bda247b88e4ff37d2f033cf757a19a80fa2420bf3dc1b11cfb24aa501b7a66db30d9d0efc82bb807219b5057011d42c8e0c74c41e53038ce6d545b106ccb54907c164110661e5a0e04339852196109168a03eb53c20185ca3790decfc0f7cba2748e2952e2532dfb2838058ffebb9e1dceb6426269c03e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109213);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/26");

  script_cve_id("CVE-2018-0019");
  script_xref(name:"JSA", value:"JSA10847");

  script_name(english:"Juniper Junos SNMP MIB-II Subagent Daemon (mib2d) Unspecified Remote DoS (JSA10847)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by an unspecified flaw in the
SNMP MIB-II subagent daemon, mib2d, that allows a remote attacker to
cause the daemon to crash, resulting in a denial of service for the
SNMP subsystem. No further details have been provided.

Note: This issue only affects systems with SNMP mib2d enabled.
SNMP is disabled by default on devices running Junos OS.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10847&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6679acff");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10847. Alternatively, as a workaround, disable
the SNMP service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

# 12.1X46 versions prior to 12.1X46-D76
# 12.3 versions prior to 12.3R12-S7, 12.3R13
# 12.3X48 versions prior to 12.3X48-D65
# 14.1 versions prior to 14.1R9
# 14.1X53 versions prior to 14.1X53-D130
# 15.1 versions prior to 15.1F2-S20, 15.1F6-S10, 15.1R7
# 15.1X49 versions prior to 15.1X49-D130
# 15.1X53 versions prior to 15.1X53-D233, 15.1X53-D471, 15.1X53-D472, 15.1X53-D58, 15.1X53-D66
# 16.1 versions prior to 16.1R5-S3, 16.1R7
# 16.1X65 versions prior to 16.1X65-D47
# 16.1X70 versions prior to 16.1X70-D10
# 16.2 versions prior to 16.2R1-S6, 16.2R2-S5, 16.2R3
# 17.1 versions prior to 17.1R2-S6, 17.1R3

fixes['12.1X46']  = '12.1X46-D76';
fixes['12.3']     = '12.3R12-S7'; # or 12.3R13
fixes['12.3X48']  = '12.3X48-D65';
fixes['14.1']     = '14.1R9';
fixes['14.1X53']  = '14.1X53-D130';

if (ver =~ "^15\.1F2($|[^0-9])")        fixes['15.1F'] = '15.1F2-S20';
else if (ver =~ "^15\.1F6($|[^0-9])")   fixes['15.1F'] = '15.1F6-S10';
else                                    fixes['15.1'] = '15.1R7';

fixes['15.1X49']  = '15.1X49-D130';
fixes['15.1X53']  = '15.1X53-D58'; # or D66, D471, D472

if (ver =~ "^16\.1R5($|[^0-9])")        fixes['16.1R'] = '16.1R5-S3';
else                                    fixes['16.1R'] = '16.1R7';

fixes['16.1X65']  = '16.1X65-D47';
fixes['16.1X70']  = '16.1X70-D10';

if (ver =~ "^16.2R1($|[^0-9])")         fixes['16.2R'] = '16.2R1-S6';
else if (ver =~ "^16\.2R2($|[^0-9])")   fixes['16.2R'] = '16.2R2-S5';
else                                    fixes['16.2R'] = '16.2R3';

if (ver =~ "^17\.1R2($|[^0-9])")        fixes['17.1R'] = '17.1R2-S6';
else                                    fixes['17.1R'] = '17.1R3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If snmp isn't enabled in some form, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  pattern = "^set snmp";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have SNMP enabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
