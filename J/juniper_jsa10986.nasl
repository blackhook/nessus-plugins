#TRUSTED 73645fdb1d831306e99c7847f1c373c4f2e99a64543dd00160a1855fe27da425c35890a799938716480f4f2c60abfb36804f95fdbd1a3707bb3f5f7c83ba2340c543a96c9134790e982a6d8556151555c0e5aab70c64b927af957e9565e0f63f75bfef0670964c160366a353ac77f4d81ae7ea512ab09157919f68418c0f3ef0adec38d2f0fdda1144a54ca26fae912cb250c59040ac3df76318db82ea69f94e2c44f5ca800d62b53d61dcc854ea7b8541312411ae20370216ffff92ce5cfacaff4c4c0bb416f183982fc29cf224d43d23e5c376088451c244960643c5dad6e4b527daa22ba9f16408cec2bd58100115eff065fedc231914cfa08a43fc6f8e8f84766ea1714c4c111d97c4a993722287db7d705ddc94f344c27dacf0e32e62e41fb131cdfc122f85e1290954939a663461827f462ee9f5278a0e18c3007640dc0107bd720a661d43c87773f94771869ab88b8d648a8fb4ee128e75c18c1f998ffc6d6a82d2b525e9a893fa0377255d479f9b267175edf04b6854f8a1b59f0e0203c31eed21b9bcfc05bc9886af992934f6c458c280ef2ce72fe36046307575e2c5a3f612d91a0a187aba2a4ab7cfa43ee0bfa628c5992ea08110f1411299b51873013095356a51f2da1b0bc1219759eadadc0a51ba28f81e87d045801011e1640d36c906ae42c83cffbe7599e0ca64a57a1005685a59065963854aac95dcdbc6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133051);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_cve_id("CVE-2020-1607");
  script_xref(name:"JSA", value:"JSA10986");
  script_xref(name:"IAVA", value:"2020-A-0012-S");

  script_name(english:"Junos OS: Cross-Site Scripting (XSS) in J-Web (JSA10986)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a cross-site scripting
(XSS) vulnerability in J-Web due to insufficient XSS protection. An unauthenticated, remote attacker can exploit this,
via injecting web script or HTML to hijack the target user's J-Web session and perform administrative actions on the on
the Junos device as the targeted user. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10986
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15e6942c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in Juniper advisory JSA10986.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1607");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

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

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.3'] = '12.3R12-S15';
if (model =~ '^SRX') {
  fixes['12.3X48'] = '12.3X48-D86';
}
if (model =~ '^EX' || model =~ '^QFX') {
  fixes['14.1X53'] = '14.1X53-D51';
}
fixes['15.1F'] = '15.1F6-S13';
fixes['15.1'] = '15.1R7-S5';
if (model =~ '^SRX') {
  fixes['15.1X49'] = '15.1X49-D181';
}
if (model =~ '^QFX5200' || model =~ '^QFX5110') {
  fixes['15.1X53'] = '15.1X53-D238';
}
if (model =~ '^EX2300' || model =~ '^EX3400') {
  fixes['15.1X53'] = '15.1X53-D592';
}
fixes['16.1'] = '16.1R4-S13';
fixes['16.2'] = '16.2R2-S10';
fixes['17.1'] = '17.1R2-S11';
fixes['17.2'] = '17.2R1-S9';
fixes['17.3'] = '17.3R2-S5';
fixes['17.4'] = '17.4R2-S6';
fixes['18.1'] = '18.1R3-S7';
fixes['18.2'] = '18.2R2-S5';
fixes['18.3'] = '18.3R1-S6';
fixes['18.4'] = '18.4R1-S5';
fixes['19.1'] = '19.1R1-S2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If J-Web is not enabled, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set system services web-management http(s)?";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as J-Web is not enabled');
}
junos_report(model:model, ver:ver, fix:fix, override:override, severity:SECURITY_HOLE, xss:TRUE);
