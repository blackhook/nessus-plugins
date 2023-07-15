#TRUSTED 0412bf01099b782cc29c43ad6d1c240e5702aa3599aff6636d8156c7d082d9ba87d2549c0f591b09952e4546a5634f8592a78be29da364ca98dda2971e05019531eda4e5cff2ebc2c3627c896ad369906da36321ce0f4d05f6fabbe274626a3e420e96df2189f5653aa49b2f1382617ce4c63b9d342e7902e217a8a08e69fb4c47e4155e4cabef3aa69d5e5fdd02cf84ad52c6d9faa1a5101ca0de55a7a142c06d4f1d852c6035b82f4f84bcf30cf4d29b35a895ff2aac5d41bda2f73e0a427a3c1d46dce96897e047af88ddefcdb542b3acdec9300708406232d04fc81c05021be8217a94360fbca8c9f66cb0314b87eeaef047e33062958af4143ee7f8db12d245bba8696ce01842aee0cd429d25d41c21650df4cf10ba9661a0fee4219959095250789e3dbbe7b7420c10e25f8e357219b2b6f2309f0770dc29965caf224e00e5ff8857296f658ea91d40dfa47286ce15ad53f5c84d08742ff8733ec3657c3efbb849c942b4b5054feea056df51f0699605c0bd320df2b6aa9465b891c3c768c07436ca276b2dacb210faf343f0d28888a50fb5c1ea8b820ad8d64debd0ef33d14d872f48f146caa04c2d5e4a53c4873ba3666a66e8e7a048eba95ae25552e8ab05e67da3dc32f0093ee38aabfbcbde06119c306e46c963771665812420d5dddb43c7a4ee99eadd75d8db70bcd7457d5e1453c570f571739bf2f0a725d2c7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88092);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2016-1257");
  script_xref(name:"JSA", value:"JSA10715");

  script_name(english:"Juniper Junos RPD Routing Process DoS (JSA10715)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
a flaw in the Label Distribution Protocol (LDP) implementation. An
unauthenticated, remote attacker attacker can exploit this, by sending
a specially crafted LDP packet, to cause the RDP routing process to
crash and restart.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10715");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10715.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

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

fixes['13.3']    = '13.3R7-S3';   # or 13.3R8
fixes['14.1']    = '14.1R3-S9';   # or 14.1R4-S7 / 14.1R6
fixes['14.1X53'] = '14.1X53-D35';
fixes['14.2']    = '14.2R3-S4';   # or 14.2R4-S1 / 14.2R5
fixes['15.1']    = '15.1F2-S2';   # or 15.1F3
fixes['15.1R']   = '15.1R3';
fixes['15.1X49'] = '15.1X49-D40';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "13.3R7-S3")
  fix += " or 13.3R8";
if (fix == "14.1R3-S9")
  fix += " or 14.1R4-S7 or 14.1R6";
if (fix == "14.2R3-S4")
  fix += "or 14.2R4-S1 or 14.2R5";
if (fix == "15.1F2-S2")
  fix += "or 15.1F3";

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols ldp";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because ldp is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
