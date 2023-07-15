#TRUSTED 7aa8ed84a6601a40c6561098cdb31533164585f91cb6387b3cb6aa928af0c8017109e763dbe1d06497fb3c01370e8af09dc37b1db72d1c6ac48cd4390d93dfcfbc41ab21cc5b7d7799e8bf71be90baebda632306c087e965a8e3a5fa9b1ecc19aeef1774e9b3644122984926a7dbd64a4724b38cfb476fb0891de1658d061d0694a923fc54117db29d62512e6ad958cffceeae2fbfa904fa5778037a4b4e438e5d44a66c3534237779a0732bc539fad69c5ffe8a30c0fa4f07483a107ddf33dd2dd6b6313582d94f8df19d1dca22a6540517ed89404a2124e5b350d4dc439bc135ff12cfc5e70a0b1d2c578a6286f9b8f504a609db65f38bf8d68f322c25671370c352ff6b109d01a669bcf6ed8ef73ed09957bc518ac04f74c2e37fc34cf7bb4b8f2fac6cc534ef99efef7af9ed221f7c694c173b3f9d1b2c791bf128eec0529effcead65d24c8859d16caddb8e7e00e640cb73089d3af4cb3bdf1708056dac3ba8f6c6a6069779968bd62be45173f45b5843c56fdacdcfa182c3bffb10043afd8d8a614a3a7c28c0abcbada11f3db1b7d5a980b41356ec0c8ea371e018cc155551e185ccc268d6b89c30838f03f42b3eeea17e95f071808bdca42c3b80942b383d94902f4c2a851fa6a1ae246ec7091082ee0ed7ce79129ca98fb74100f61e4457f90f3fac941e4ed6b31e9d44c710c1e4d3c3bdcd33e220271aabed6bc02e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130519);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0062");
  script_xref(name:"JSA", value:"JSA10961");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: J-Web Session Fixation Vulnerability (JSA10961)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a session fixation
vulnerability in J-Web. This allows an unauthenticated, remote attacker to use social engineering techniques to fix and
hijack a J-Web administrator's web session and potentially gain administrative access to the device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10961");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10961.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0062");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

fixes = make_array();

if (model =~ "^EX")
  fixes['12.3'] = '12.3R12-S15';
if (model =~ '^SRX')
{
  fixes['12.3X48'] = '12.3X48-D85';
  fixes['15.1X49'] = '15.1X49-D180';
}
fixes['14.1X53'] = '14.1X53-D51';
fixes['15.1F'] = '15.1F6-S13';
fixes['15.1'] = '15.1R7-S5';
fixes['15.1X53'] = '15.1X53-D238';
if (ver =~ '^16.1R7($|[^0-9])')
  fixes['16.1'] = '16.1R7-S5';
else
  fixes['16.1'] = '16.1R4-S13';
fixes['16.2'] = '16.2R2-S10';
fixes['17.1'] = '17.1R3-S1';
if (ver =~ '^17.2R3($|[^0-9])')
  fixes['17.2'] = '17.2R3-S3';
else
  fixes['17.2'] = '17.2R2-S8';
fixes['17.3'] = '17.3R3-S5';
fixes['17.4'] = '17.4R2-S8';
fixes['18.1'] = '18.1R3-S8';
fixes['18.2'] = '18.2R3';
fixes['18.3'] = '18.3R3';
fixes['18.4'] = '18.4R2';
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

junos_report(model:model, ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
