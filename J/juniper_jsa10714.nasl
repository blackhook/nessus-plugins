#TRUSTED 11f94f522d2830f54a063e80c3257b022933d3ef6c2044af5895dc18e503635fb358f5a8b482f892c58b9f6fbe1b7325ecd6329549d36ce5e15fd54f3eb6827085892a30924705a3710ce9a27cc9386a13579571d654be0049086e2302c3cd9d6b5650c37d74ab10c6685384941614d19d21fb0d60fd04c511351d0aa7f4bbf4957af84a52bfbdc1796f57ab850c396ca7872e5ef44d48319acee020f1601e7391d898e10d5eca6037fe0311e285b69f3ef1938d16f8610de6a54a4e75ca638f3f99f29e8be271b388164b55e9ba545e3338dd6656eb99b2eb20bd31001ad78da31e1831eb6511d09f52309d8e56af1b3e85b93f4d342f120afce6289de12729fa1fffb4e759bb8ee9c0e90355942f3f4d71297083a5794496a14c5a36f6a92797c49c99446d4254037ff48755e20c1c11bfd1c204b9c6ac9a85e3516ed924ac1aa3f014b7cf2067273e1404f5a4628ef27a217e1816dd30502bd221af3b47cfe7dc12be7a8d71d1a545d86baa025c6193ce77dd46557742cd4a89f97500c689341d1027d33a676e06c1a7634d42513de0fcad20f0bc753cc6da0f5169ec6688201f9507ce322a994381ee63e49cb56593d4c924094cb407dab5c6ba00dfedecabe3b7637495815a13d925aa86459f2cc3327dde41bdd94cfe6e8e4d2e43574ae654718f8cda7dae9fa3e2c421c0bc083a95a43845c47dd3d74ae9e6d5ec787d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88091);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2016-1256");
  script_xref(name:"JSA", value:"JSA10714");

  script_name(english:"Juniper Junos IGMPv3 Protocol Multicast DoS (JSA10714)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
a flaw in the IGMPv3 implementation. An unauthenticated, remote
attacker can exploit this, via a specially crafted IGMPv3 packet, to
affect service availability on a portion of a multicast network. Note
that IGMPv2 is not affected by this vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10714");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10714.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/12");
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

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X44'] = '12.1X44-D55';
fixes['12.1X46'] = '12.1X46-D40';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3X48'] = '12.3X48-D15';
fixes['12.3'   ] = '12.3R10';
fixes['12.3X48'] = '12.3X48-D20';
fixes['13.2'   ] = '13.2R8';
fixes['13.2X51'] = '13.2X51-D40';
fixes['13.3'   ] = '13.3R7';
fixes['14.1'   ] = '14.1R5';
fixes['14.1X53'] = '14.1X53-D30';
fixes['14.1X55'] = '14.1X55-D25';
fixes['14.2'   ] = '14.2R4';
fixes['15.1'   ] = '15.1R2';
fixes['15.1X49'] = '15.1X49-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols imgp";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because imgp is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
