#TRUSTED 4e2fe1f04442c89abeea8b91a09fcfc448928c56ef7ef3c9a602105725a76eaafabb310b50b81465d8305ab357a49eb0bf612d0fa6570678f6418afb9c01a8bb4e7a11409f797ec177aebf180913a2dd29dda3577609cad3fbf6470c9c683e4134ffcf6d143da9e4a615f7dae369452dbbfd83e34c588aeb0284e8f5997d0e7ee1188016b25aa24c1d142cedca55a0c3864779e25256e1784dd1d8db82dd9bff7475c5499723fc4dcdc867e67494f57d8b7b4ea5f9350b204663b1e1c34b63ebe8e04b1dfeddc2ba6f27253e31ba74ac3c031f96e2255eefc8e3e9b728af90a0a3934692c7fff4c9d88c1089ebc1014ffb30ab84f1c0f48330689b57f3c3f9e65b8de96ce405506b16b75884cfc24e9868749281e87c8042d6d317dbc4c190dab752f4f05f911fa804f897e85f799d0ffa7682cd853c550b6dcf53421203dae3f1812cf44c113bab74e49799e34529f8e8f45c81088b6be32f90ddce9c8fb7dfdc31093f71c88ae81732e2a6f400a9c5ffa2b4b128d400cdccc40a7ecf71ba6584ff832d80545dfbc532ba02b3f583efd5dbd0161195c6884f62930e673b44e7931e3f12726fb40472ca488a4dfdb32e0d1c14140ac1f861260a9706360830ecada35dbaa147c596fa776767cece5ab5a605a4c121f9f4ce4b73c1ea1aee43a63357564e7a2a84eb4f2621060564119f8621f0f6e7e2206224b06b959a7708bd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104039);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-10618");
  script_xref(name:"JSA", value:"JSA10820");

  script_name(english:"Juniper Junos BGP Update Vulnerability (JSA10820)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a vulnerability in the 'bgp-error-tolerance' feature 
that when enabled, a BGP UPDATE containing a specifically crafted set of 
transitive attributes can cause the RPD routing process to crash and restart.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10820&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e14fb2fe");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workarounds referenced in
Juniper advisory JSA10820.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');


# Affected:
# Prior to 13.3R10-S2
# Prior to 14.1R8-S4 or 14.1R9
# Prior to 14.1X50-D185
# Prior to 14.1X53-D45 or 14.1X53-D50
# Prior to 14.2R7-S7 or 14.2R8
# Prior to 15.1F5-S8
# Prior to 15.1F6-S7
# Prior to 15.1R5-S6
# Prior to 15.1R6-S2 or 15.1R7
# Prior to 15.1X49-D100
# Prior to 15.1X53-D64 or 15.1X53-D70
# Prior to 16.1R3-S4 or 16.1R5
# Prior to 16.1R4-S3 or 16.1R5
# Prior to 16.2R1-S5 or 16.2R2
# Prior to 17.1R1-S3 or 17.1R2
# Prior to 17.2R1-S2 or 17.2R2
# Prior to 17.2X75-D50
# Prior to 17.3R1
fixes = make_array();
fixes['13.3']     = '13.3R10-S2';
fixes['14.1']     = '14.1R8-S4';
fixes['14.1X50']  = '14.1X50-D185';
fixes['14.1X53']  = '14.1X53-D45';
fixes['14.2']     = '14.2R7-S7';
fixes['15.1']     = '15.1R5-S6';
fixes['15.1X49']  = '15.1X49-D100';
fixes['15.1X53']  = '15.1X53-D64';
fixes['16.1']     = '16.1R3-S4';
fixes['16.2']     = '16.2R1-S5';
fixes['17.1']     = '17.1R1-S3';
fixes['17.2']     = '17.2R1-S2';
fixes['17.2X75']  = '17.2X75-D50';
fixes['17.3']     = '17.3R1';

if (ver =~ "^15\.1F[0-5]")  fixes['15.1F'] = '15.1F5-S8';
else if (ver =~ "^15\.1F6") fixes['15.1F'] = '15.1F6-S7';
else if (ver =~ "^15\.1R[0-5]")  fixes['15.1R'] = '15.1R5-S6';
else if (ver =~ "^15\.1R6") fixes['15.1R'] = '15.1R6-S2';
else if (ver =~ "^16\.1R[0-3]")  fixes['16.1R'] = '16.1R3-S4';
else if (ver =~ "^16\.1R4") fixes['16.1R'] = '15.1R4-S3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols bgp bgp-error-tolerance*";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, "affected because the 'bgp-error-tolerance' feature is not enabled");
  override = FALSE;
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
