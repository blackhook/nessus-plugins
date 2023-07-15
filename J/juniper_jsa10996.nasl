#TRUSTED 2156a0f88eae7236c2146425a20608ea5e9c176c5963324336e632e8f89ee5c5ffc8aa4a38640f5dd985eb1de18ef5ed34b2c5b376dd4a6cd3e965bfe620cc374db36a221b35cd8f14dbbf08690a9beb097e1777d0a5c217721b124d8bb697f1aa75fce2cc4a6562901082c2f75f84ea495f8ffa1ebe7d63d2ec40130ab1e17d365509739008bdd80593f4375ec2f49b146d1b67d90d6c00a666fc6de0829840530135ca892f0f5ce45daeb030167a68c0ffcf7057cb5419361d45018400c0f4fc3bcca6e20032433731383c6551ffbf4688e8160cc2fc07df631e98d6ca4e68b5db384784fef3c9d2ea59401d68448b81275b69d932a7cb6995e365516bd86fdadb42f58878a1530ff6b9b979aa4a016baeb3c68855b31abfdf3221fcda058e1abe72fe87c8b39dab1a8a9ca37ca16f17383704aaf478fa8fd833661e4a85191a75139087785c21dc2cd554d047afd0c5f21104c0ebb14ed83938ee2f7bd0d80a44e1e1676409e57c8d2bed4ec5c511639a7302834a515696098290f91a1f3a28c8070fe276c0f6d3dc9d4de32abc9666f2745e63f77f6bc551d772565aa6e89978e8ae11a89cc7ef1a9773cd77ac8350c01b535ce60571004c35334ab1880b1c7d1926098e9ebbfae6e5a3c6c32d4e1b6753d161bb1b3f26476109167853fd60ba4b938853952576e7ad73186dfb6d751f7a6960e3986ed85cc1942adbb162
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136119);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/14");

  script_cve_id("CVE-2020-1613");
  script_xref(name:"JSA", value:"JSA10996");
  script_xref(name:"IAVA", value:"2020-A-0162-S");

  script_name(english:"Junos OS: Established BGP Session Termination Vulnerability (JSA10996)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is 12.3, 12.3X48, 14.1X53 or prior to 15.1R7-S5, 15.1F6-S13, 15.1X49-D180, 15.1X53-D238,
15.1X53-D497, 15.1X53-D592, 16.1R7-S7, 17.1R2-S12, 17.2R2-S7, 17.2X75-D102, 17.3R2-S5, 17.4R1-S8, 18.1R2-S4, or
18.2X75-D20. It is, therefore, affected by a vulnerability in the BGP FlowSpec implementation. An unauthenticated,
remote attacker can exploit, specific BGP FlowSpec advertisement, in order to terminate an established BGP session
as referenced in the JSA10996 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10996");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10996");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1613");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (ver =~ "^12.3R" ||
   (model =~ "^SRX" && ver =~ "^12.3X48") || 
   (model =~ "^(EX|QFX)" && ver =~ "^14.1X53"))
{
  security_report_v4(port:0,extra:'This version is vulnerable. Please, check the vendor\'s advisory for more info.', severity:SECURITY_WARNING);
  exit(0);
}
fixes['15.1'] = '15.1R7-S5';
fixes['15.1F'] = '15.1F6-S13';

if (model =~ "^SRX")
  fixes['15.1X49'] = '15.1X49-D180';

if (model =~ "^(QFX5200|QFX5110)")
  fixes['15.1X53'] = '15.1X53-D238';

if (model =~ "^NFX")
  fixes['15.1X53'] = '15.1X53-D497';

if (model =~ "^(EX2300|EX3400)")
  fixes['15.1X53'] = '15.1X53-D592';

fixes['16.1'] = '16.1R7-S7';
fixes['17.1'] = '17.1R2-S12';
fixes['17.2'] = '17.2R2-S7';
fixes['17.2X75'] = '17.2X75-D44';
fixes['17.3'] = '17.3R2-S5';
fixes['17.4'] = '17.4R1-S8';
fixes['18.1'] = '18.1R2-S4';
fixes['18.2X75'] = '18.2X75-D20';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "bgp .* family inet flow";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
