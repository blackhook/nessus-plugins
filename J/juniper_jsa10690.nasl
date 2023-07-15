#TRUSTED 277f5484469deafbcd8afb37f09d075af10971585f24714a2372f980b867d28282537dc76d412778138fccdb6971e6e3b470ef77422afd5bcfa6e930054f342a4620fce21832c6b99d47c02bd43b8aabe2e0b13062a9f0b0536ba2aba52d45b35b1c9c5f6b8f48a0bbfbcb197d7cdadd3686214d08d44c21ab919ff600ab63cab8758657b5f2c20d56e45364a45ba54a37ee7b65fc910f4d58ec6f7492e067bd585ce00702263817227e1439d8a8961d9a1bfcb51013021bbc943f6f63e3ca64c81dcda62be5f60eb25ffa60269218efa8039582e5c439f6347e51d1ffb73d6ffff03c89e7eb5c83e2c9c6160fdd5a1cbc93da5867aa64fd7cdb7ce4c19702a97eda64dd1ba964f9a527fa0f6600c2abbc7d2653af08e1c1994275c2e3f045027a4be2dc1dff6bf8e12f272594ce0e3c173822e57445f3b82e4842c6462ea430d7ef7c5a117ef1291c1a919a9562ecfb3343675548941acdc8b801d7c05d6c5a7f07b941d3669fbf652666f1955d5ab21451d78cc2950155dfe596203540e9732b9d157afbb804332677e23fd625e1c0b8bcb277fa5a076ed27f858173b90597c79b47847dc4e9e55cb32fea16572f4b3e2b736af162377513c0a5444ba7fae3343185eb8cc68a94c854614288726fc9b09c1297c2119ebdf0aabb75c9952656d026e8c845dcb1ce83c6673eb4a766590ddea5dc803c6cf997db7856f4186b57
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85229);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2015-5362");
  script_bugtraq_id(75721);
  script_xref(name:"JSA", value:"JSA10690");

  script_name(english:"Juniper Junos bfdd RCE (JSA10690)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a remote code execution vulnerability in
the BFD daemon (bfdd). A remote attacker, using a specially crafted
BFD packet, can exploit this to cause a denial of service or execute
arbitrary code.

Note that this issue only affects devices with the BFD daemon running.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10690");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10690.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();

fixes['12.1X44'] = '12.1X44-D50';
fixes['12.1X46'] = '12.1X46-D35';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3']    = '12.3R10';
fixes['12.3X48'] = '12.3X48-D15';
fixes['13.2']    = '13.2R8';
fixes['13.3']    = '13.3R6';
fixes['14.1']    = '14.1R5';
fixes['14.1X50'] = '14.1X50-D85';
fixes['14.1X55'] = '14.1X55-D20';
fixes['14.2']    = '14.2R3';
fixes['15.1']    = '15.1R1';
fixes['15.1X49'] = '15.1X49-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show system processes");
if (buf)
{
  if (!junos_check_config(buf:buf, pattern:" /usr/sbin/bfdd "))
    audit(AUDIT_HOST_NOT, 'affected because the BFD daemon is not running');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
