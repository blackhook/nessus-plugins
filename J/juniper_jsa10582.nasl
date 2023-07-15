#TRUSTED 33b2432d34ad2ad6eab3d12263f9ab70c5d9aa4e4a150b4c222c5228840c15018d12a7fef72cb8415fd19df170dd0813db9d58d8b2282ed45b6a27fdbd6e4d7e3d69c640f6b7217b6d0d8cb38615649ef10aac11bbe10e2a4c9fa1ffed795ce24a05f6e4e49fb5d3dfe02d7a564f48fc1f5682ed3727886d121edd8683d916a8a6393dff19fe70caebff28cfdb100d0bb8f7a4d72a3fcf010d9dd20cc7306a9aaedf6aec2cfc4a15b207cf454ae8c15a1f129531f9acaf5e1d6f20eeeca59dfab62d1a5d61f5600a882e8c41bf1ea0f32cfb3297595e36fad96a8ab11abd8f4e9509a98da4fcd34ff75448f72bd43ad387a16e4848bb6c4522f64fb26d17ace27d7c2575c3ad6eb185dd5e03833cf8f31d86e9b0fc90827c0087820f6ea62249f251a0ab82ef4662679f23b001bb7f9cc3fa706c315247d77dbf0b4db2b52d22e33e2b76a403b3b80d88b0b22b8ab5ec84f5bdc24adff5904fba7ae7ae62c0cb308b0e797205ee98ce4352d77df3b8cabef327183e2b84b6b0507efd49fc615418e265cdbd21d923acfc0fe587d289633115be524c73e3dcab2585082ece0c6dc6f4adfd0add95736f4d541182fda641ead64fa3617735e770448fe54b3d4e669ab4d32bae0397d2c54d36cabbbf5a4984346fc83df7144b99db13f8467df0999712fda10378f281e023b5992fe93a4566eefff6c0e788f26d738c6e26c3f4fe
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69194);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2013-0149", "CVE-2013-7313");
  script_bugtraq_id(65169);
  script_xref(name:"CERT", value:"229804");
  script_xref(name:"JSA", value:"JSA10582");

  script_name(english:"Juniper Junos OSPF Protocol Vulnerability (JSA10582)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device has a flaw in its OSPF implementation. A rogue router in
the same autonomous system (AS) could exploit this to control the
routing tables of all other routers in the AS.

Note that this issue does not affect device with one of the following
configurations :

  - Interfaces not configured for OSPF

  - Passive OSPF interfaces

  - OSPF configurations that use MD5 authentication

  - OSPF interfaces that block external parties from sending
    OSPF link-state update packets");
  script_set_attribute(attribute:"see_also", value:"http://crypto.stanford.edu/seclab/sem-12-13/nakibly.html");
  script_set_attribute(attribute:"see_also", value:"https://www.blackhat.com/us-13/archives.html#Nakibly");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10582");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10582.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-07-25') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4R15';
fixes['11.4'] = '11.4R8';
fixes['12.1X44'] = '12.1X44-D15';
fixes['12.1X45'] = '12.1X45-D10';
fixes['12.1'] = '12.1R7';
fixes['12.2'] = '12.2R5';
fixes['12.3'] = '12.3R3';
fixes['13.1'] = '13.1R3';
fixes['13.2X50'] = '13.2X50-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if OSPF is enabled without MD5 authentication / passive mode
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols ospf .* (authentication md5|passive) ";
  if (junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, "affected because OSPF is not enabled or OSPF is enabled with MD5 authentication or in passive mode");
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
