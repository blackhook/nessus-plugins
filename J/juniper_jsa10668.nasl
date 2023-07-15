#TRUSTED 354862ba1253c84db2b5d0f6a08208833376919af459b9db933a4a3cfdd15aaef32c43031b868d1db6dafe88d684267584afd9f614a82dbd8976229160e6cbae3459e2ae285a9de689c9524349a9792b066ab85268086c7ad83766fe56df31ff6dc1df304d3220d4c4afc48c1ddd6df09c556598e2cacb48169e8a50e2f3c10d1ae452d8a73349f8efb0fcba80c06321cce6fcb73a45b9d4d23684e9be337b523f9d7bbd8b22c84eac9cb7ba8942aae89cded6514e029dfdccfe2be5b82708e80dbac1d24124d3abcb8d48af2da8cca961917f86cad294c367b7018c2ce8f65e98390f22e99709ed1e74d868fe4f0ccdc2fc93465b539026cf02866cffa03551341eb57ccca9e09160f530ef20029210b827a62ce02cdfaa2bc8ba07fcd786439344a1d73891b544afb1a9b00af7cd662fb8d4d5a9cdb07b0de4b737687ac2f4ee758b969e3d9d44d72a51225210ed517e3d0fa0da2fc02f5ac6aaf543ddc0e5fb371d5b5b9227c20ef3fd13ea144fda0e4a06ce2fca297665850df91c123be6368f9d344d4c20ecc0b302812d32d36373fd4be57c58dada3816b17be6b3c84c5acd27d159290a33adbf9b2ca4c680ddf92475ff5b2750d4ebbece328ef56b3e9df9e11e25c81e6522df65f2cb21aa697f1882feb02e042ecc9bab205d14eb1a1a9034d59f2080445344592a1466e462150beb43cb08a490107bd9acbcbf9f81
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80956);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-6385");
  script_bugtraq_id(72072);
  script_xref(name:"JSA", value:"JSA10668");

  script_name(english:"Juniper Junos Fragmented OSPFv3 Packet DoS (JSA10668)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability when
processing fragmented OSPFv3 packets with an IPsec Authentication
Header (AH). A remote attacker on an adjacent network can exploit
this issue to crash the kernel, resulting in the Routing Engine (RE)
restarting.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10668");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10668.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

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
fixes['12.1X44'] = '12.1X44-D45';
fixes['12.1X46'] = '12.1X46-D25';
fixes['12.1X47'] = '12.1X47-D15';
fixes['12.3']    = '12.3R9';
fixes['13.1']    = '13.1R4-S3';
fixes['13.2']    = '13.2R6';
fixes['13.3']    = '13.3R5';
fixes['14.1']    = '14.1R3';
fixes['14.2']    = '14.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols ospf area \S+ interface \S+ ipsec-sa \S+";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because OSPFv3 IPsec authentication is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
