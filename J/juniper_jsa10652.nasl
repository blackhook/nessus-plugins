#TRUSTED 3755de5f311b7202ff9a38a40db37d80486dca7b478e9448dc432f6a1ba5f72606db1c973a792e7c434f8eb1dc72a275fd66c1bef1db10d976e1cc575694861de59ebb70d2a74d255079451927e16db9b306a2395277842c0f2b6b76534c590009c429328c9e51c1a68fb28e26c84250ef31acb0631e61c556934a6765d49488455dcf7b19119ca18bbe5aa23179f7d64f11106d4ce05a7fb8ed3adf216b1b78b6f9285e4c67c80310de5f8c8478e17cf2c341c32e6cde7a89ce10e7ca273a1b6d95adbf5f72ba9ea12970069ba025f25413f11ae71695c47ec9c76a9abe4ac959e2896f8d9d04f4a3443af32fc8a00da9d4bd4fb242b5639f158d4a92398fa6887708f005aad34a4100f81c7432da3eaf0ae995e75aa2f88ac0ab213cd0124fbdeb833c4f2be62e8d7729773a0cd7f427e573faa449de6764a69422006c07f566f76a469857fe5cea7b0becadbc179a6f4e3d774d93a3575c1c37d1418cb60222f136d110afbccffe601cbc8a345a23dfdd9db572c8e263cc0ea753b25927529af65c550c456fd1c3ff673b266d78b111dd5c3aa84d842fbb4c5340e94691075be22a9edb8f00ceac61157146cd8f655e661c785a0ee95120d90bd3d87b361810b6818204ba6f062699b4224938e53338285c69b562d1db393cf6458f66a11e93b8af8d8baca498bc2b7d9304f8037d60b62489621d5dc9c39462581578b529
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78423);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-6378");
  script_bugtraq_id(70363);
  script_xref(name:"JSA", value:"JSA10652");

  script_name(english:"Juniper Junos RSVP 'rpd' Remote DoS (JSA10652)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
improper handling of RSVP PATH messages. A remote attacker can exploit
this issue, by sending a specially crafted RSVP packet, to crash the
'rpd' process.

Note that this issue only affects devices with support for RSVP
enabled on a network interface.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10652");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10652.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['11.4'] = '11.4R12-S4';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D30';
fixes['12.1X46'] = '12.1X46-D25';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R9';
fixes['12.2X50'] = '12.2X50-D70';
fixes['12.3']    = '12.3R7';
fixes['13.1']    = '13.1R4-S3';
fixes['13.1X49'] = '13.1X49-D55';
fixes['13.1X50'] = '13.1X50-D30';
fixes['13.2']    = '13.2R5';
fixes['13.2X50'] = '13.2X50-D20';
fixes['13.2X51'] = '13.2X51-D26';
fixes['13.2X52'] = '13.2X52-D15';
fixes['13.3']    = '13.3R3';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == '13.2X51-D26')
  fix = '13.2X51-D26 or 13.2X51-D30';

# RSVP must be enabled on a NIC
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols rsvp interface ";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because RSVP is not enabled on a NIC');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
