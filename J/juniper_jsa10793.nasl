#TRUSTED 6be211fb9a7ffd414d3c2214d0318da04dafc469d297800bb2023f5244b3f20fa3f5963f113be20923ee399d4b36fe315b386d52f64f4060fca0234afb458b9bc3e8b13cba740ceab8cfe7c97684e3d63b3e79677222e4bb9cb84c8bd38c5c54f7bd5a90a6bacc25e0188d2c5c81479d3dd1d6da0493e860be51e531658614522b74391d57ff2e7cff4ed195ec4bb759f6732e9690b16c3712299d52c6f4d4cb330e4f2c36a4e8ee1900b822acf76760c66ae5de7979e34697ede24de1236a9d013a57fec8cc74a68c835599884dfedad2bd05a9d06a03295b95ed71b79cc1521622064f1c18e696e89397490439987d924d7f471351e75ac4e1011894300051aefcfc3c08c4cefd766358abe55cc940d3db8e3e489f8f58c5cd14a7d3cef3424882a155765d55e2d0adff4880424ccd72e19f8ef7f42d9104fcdc4fc092073802046da1a4d9cec43956dc4fd78ceb094c848aba1f17f054f05c3cc28b440aba44746e79d6d138575440a151fadb53a0b5381d9a755696aa2b7f068146dcbd809582dfc515daca0a61febfd68627d79e471a3a55d47312a743a2bc718613ff2937da9392563a7d52055117a31b05276b327b63cc2d21572dde067664eecd291df1bac91ed06181a38868807a9c9e3c3d9ecef2bef0012a9411c78dc4fb2e7c668eb70549af1ca2b3e8ee540d563d15e2eee69ee89c2d55cb9810604603981992
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102706);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2345");
  script_bugtraq_id(99567);
  script_xref(name:"JSA", value:"JSA10793");

  script_name(english:"Juniper Junos snmpd SNMP Packet Handling RCE (JSA10793)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a remote code execution
vulnerability in the snmpd daemon due to improper handling of SNMP
packets. An unauthenticated, remote attacker can exploit this, via a
specially crafted SNMP packet, to cause a denial of service condition
or the execution of arbitrary code..");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10793");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10793. Alternatively, as a workaround, disable
the SNMP service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

fixes['12.1X46'] = '12.1X46-D67';
fixes['12.3X48'] = '12.3X48-D51'; # or D55
if ( ver =~ "^13\.3R10")      fixes['13.3R'] = '13.3R10-S2';
if (ver =~ "^14\.1R2")        fixes['14.1R'] = '14.1R2-S10';
else if (ver =~ "^14\.1R8")   fixes['14.1R'] = '14.1R8-S4';
else                          fixes['14.1R'] = '14.1R9';

fixes['14.1X53'] = '14.1X53-D44'; # or D50, D122

if (ver =~ "^14\.2R7")        fixes['14.2R'] = '14.2R7-S7';
else                          fixes['14.2R'] = '14.2R8';
if (ver =~ "^15\.1F2")        fixes['15.1F'] = '15.1F2-S18';
else if (ver =~ "^15\.1F6")   fixes['15.1F'] = '15.1F6-S7';

if (ver =~ "^15\.1R4")        fixes['15.1R'] = '15.1R4-S8';
else if (ver =~ "^15\.1R5")   fixes['15.1R'] = '15.1R5-S5';
else if (ver =~ "^15\.1R6")   fixes['15.1R'] = '15.1R6-S1';
else                          fixes['15.1R'] = '15.1R7';

fixes['15.1X49'] = '15.1X49-D100';
fixes['15.1X53'] = '15.1X53-D47'; # or D48, D57, D64, D70, D231

if (ver =~ "^16\.1R3")        fixes['16.1R'] = '16.1R3-S4';
else if (ver =~ "^16\.1R4")   fixes['16.1R'] = '16.1R4-S3';
else                          fixes['16.1R'] = '16.1R5';

fixes['16.2'] = '16.2R2';

if (ver =~ "^17\.1R1")        fixes['17.1R'] = '17.1R1-S3';
else                          fixes['17.1R'] = '17.1R2';
if (ver =~ "^17\.2R1")        fixes['17.2R'] = '17.2R1-S1';
else                          fixes['17.2R'] = '17.2R2';

fixes['17.3'] = '17.3R1';

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

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
