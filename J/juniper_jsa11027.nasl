#TRUSTED 1faa0386244ff0c16b5e8a324d38fc66507796daa5001128cfbab5e7ba905ec7eeb3fc066aca0639c323fb2db92b424910d433855556f9b118837753088e9f93e0bb51ec44423876263537253370d7fdb12683bafba3595bf4bcf471a0aac2942d35bb09f3058cb84c24d6d5f2bdc12ab84a820eac3a90df58793f1796839f8b1a35107a08d9ac11daccc51e969c1c1ceca34404a6d48eefeb1cb0c6ca48762e5509582ae0dccad2824cb07d96d85bd6eab07e09bb513a0b4ac47f546d570be105075256cbd5d589c03c9ff69bfd86b769831e6968208ba087edc3824e9152dc7df9be248e63fec390638397165dc6415c13f664cb4365eb7b9b801e69051c73add7ae17723ce4a5a35b2f95793c98b85cb25ead316b91e3b9a971e0554f14e6a7f5538fc0381114e24ec916f5a29b0ff5d03e669d9d21b221c80a8e29fe7409da197d10fc92f7eae71c6ef2de857d9240e48e9b98425e6fa6d2e87155efa3b42019524be8f17238d3a12a2c0c8db2f4c8864d0203a355e63041d1c67fd9da24c77355674127ebad23df70c004e077c36e2e7461950c088010aacc7d0c928bcc23fd28574c322048fd29feeba3346bae0bd9aab8e97e31ab4400a838c0e5a081f6f2494d93aa32a83c4a2cc76ff9fb6820384446f26b725a3cb1f838d46558cd2745d4bbb3dceb39ea7e79123e63d98947269ae44a321988c1753feccca66956
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138596);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/27");

  script_cve_id("CVE-2020-1641");
  script_xref(name:"JSA", value:"JSA11027");
  script_xref(name:"IAVA", value:"2020-A-0320-S");

  script_name(english:"Juniper Junos LLDP Packet DoS JSA11027");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version of Junos OS, the remote device is affected by a denial of service (DoS)
vulnerability due to its implementation of LLDP. An unauthenticated attacker can exploit this, by sending crafted LLDP
packets from an adjacent device, in order to cause LLDP to crash.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11027");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11027");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1641");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['12.3'] = '12.3R12-S15';
fixes['12.3X48'] = '12.3X48-D95';
fixes['15.1'] = '15.1R7-S6';
fixes['15.1X49'] = '15.1X49-D200';
fixes['15.1X53'] = '15.1X53-D593';
fixes['16.1'] = '16.1R7-S7';

if (ver =~ "^17\.1R3")
  fixes['17.1'] = '17.1R3-S2';
else
  fixes['17.1'] = '17.1R2-S11';

if (ver =~ "^17\.2R1")
  fixes['17.2'] = '17.2R1-S9';
else
  fixes['17.2'] = '17.2R3-S3';

if (ver =~ "17.3R3")
  fixes['17.3'] = '17.3R3-S6';
else
  fixes['17.3'] = '17.3R2-S5';

fixes['17.4'] = '17.4R2-S4';
fixes['18.1'] = '18.1R3-S5';
fixes['18.2'] = '18.2R2-S7';
fixes['18.2X75'] = '18.2X75-D12';

if (ver =~ "^18.3R1")
  fixes['18.3'] = '18.3R1-S7';
else if (ver =~ '^18.3R2')
  fixes['18.3'] = '18.3R2-S3';
else
  fixes['18.3'] = '18.3R3';

fixes['18.4'] = '18.4R1-S5';
fixes['19.1'] = '19.1R1-S4';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set protocols lldp";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
