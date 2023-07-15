#TRUSTED 29c5a94c1a64e7d6cfafab29fdf676b2a518fe5d86ad9a10783d71074bf2b1fa965d282147f337dc83db723b3d74a30c89aba0343a88a91b512ca0539c9faf209e41b04ee23faf6e25a8216986ebec0f0f1fd121abf0a81eb0b20497a8d9cb368380b2ef868b50ca89eb36a3ad12a2554010844faef76225c023db469ad8a5a777b9a67a14aca6f63c44a16257900b5d8c1a6004c24cdca432aa44dbd81f60db7282c2bba930a54d70675ecdb147ebcc47c88ad17e9d7167dab16236dc28a747f852b75fb6c234c918338c285abab2a62ecb3dba713653defb0ac6a22ac4cd6cd1faa5abf74ef128702e28853fda50316f37e10cc2de3fb10424cb4a17a7c9cfff42ca95dffaaaf260b2e0bc6f7fb02e32418acc23a69b66d58c0db67e29a50650f24f3b13e4186e9bdd2c9faef4a6a2d718e08cd7e008a5c5f55b697a8b5471195c38c88699a02abdd9b02384d2152f821983580a5c9d1a3a336ca7a10b284ba49b8a3974590086c5af0f3debc3f7cbea8615ec17ac2308e8a5afc157f42b28a843ba02f7c192e24e37bbbcb2aad9f3f49658bfa4cae21d1fbde939a491d5c1b4f83894b7efaaf5a929ffacc99e50e84e07a625c5395e16ada8104b8b0a2f78d5702e8c8e79bfa9758e8c412a3ab8d29b7ac0fd29d8ca2e06110722b8c7fa0bd9e725513560845d35113666822768b96b592384e38a66324642c985352680ca
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109210);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/26 18:36:16");

  script_cve_id("CVE-2018-0016");
  script_bugtraq_id(103747);
  script_xref(name:"JSA", value:"JSA10844");

  script_name(english:"Juniper Junos Connectionless Network Protocol (CLNP) Packet Handling Unspecified Remote Code Execution / DoS (JSA10844)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by an unspecified flaw that is triggered when
handling Connectionless Network Protocol (CLNP) packets. This allows a
remote attacker to crash a device or execute arbitrary code.

Note: This issue is only affected if 'clns-routing' or 'ESIS' is
explicitly configured.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10844");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10844.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

fixes = make_array();
fixes['15.1']    = '15.1F5-S3';
fixes['15.1']    = '15.1F6-S8';
fixes['15.1']    = '15.1F7';
fixes['15.1']    = '15.1R5';
fixes['15.1X49'] = '15.1X49-D60';
fixes['15.1X53'] = '15.1X53-D66';
fixes['15.1X53'] = '15.1X53-D233';
fixes['15.1X53'] = '15.1X53-D471';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for CLNS routing and ESIS
override = TRUE;

buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set routing-instances \S+ protocols esis",
    "^set routing-instances \S+ protocols isis clns-routing"
  );
  foreach pattern (patterns)
    if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;

  if (override) audit(AUDIT_HOST_NOT,
    'affected because neither CLNS routing or ESIS are enabled');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
