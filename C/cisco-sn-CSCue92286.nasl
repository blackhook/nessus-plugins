#TRUSTED 0366d37a6e14a4abbbd92d8f6786ee52a74e3b0b68161cd54cf9b2b682ff508b46d9fe43024e6bac974bc87cb627517762eb4ec6e46ce8fb52eeb8987453fd1f50e00b575abebadab3c084e7dcf2011df91d25853ea404093db160222524b4c8953993897b4d015c4894805cc4b1b3eb9deda4fa290b3f0f6aeaa9ad57867e0d4feb2a8a2023147be17f8673ee4fbef603fd16a49157c83e0673c2a66a8724a63c69e526b1c8eef68d9b60f3b88d395e74877d38b39f5277792a6c4004fa36e82646caad2b5dcbd9c977e621f438b68a074a98bb6b480a888b467a0f6e9febd33b464c09772673ab58b75885900dee48b39247a46300a6806c1a4a0c4c67682a4a343c6000fd1c480fcaa92738cc309e8c0f343ad05db7d6b4c63817a7b2e998411fe8618936fc99dd26e005eb834f6f9431e49560ea44ae4a0e4ea2c091ffcd90adaec14b391e918ae7a2d1beb6e2037966a2cdb8e794a221e2df8bc30dfeedab4ed81e68bf6d95dc1261745c49acfc27a31f1c21801dc2695854242ab87c9dc2d223db40ed6b2e4949dc683ab660580307dfa2480e31de5226d2b0b328a6f9c34c6155ccc7a974fb7f312f841a8c3d15f503503906bda0096d96f94827a85ba10f1e1f5a7645546b541d5542261acda9f95ff3c4d46b6d4ff10ed0443e9f1c9e0706c76dd9edd146cc6769936d26ee08a2f6c3e761f7828a740fe59b319e36
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70894);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5522");
  script_bugtraq_id(63342);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue92286");

  script_name(english:"Cisco Catalyst 3750-X Series Switch Default Credentials Vulnerability (CSCue92286)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is running a vulnerable IOS version.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device potentially contains an issue which, due to
default credentials on the Cisco Service Module, could allow a local
attacker to gain unauthorized root access.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31496
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd2608be");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in Cisco Bug Id CSCue92286.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '15.0(2)SE1' ) flag++;

# check model
model = get_kb_item("CISCO/model");
if (model)
{
  if (model !~ "catalyst3750") audit(AUDIT_HOST_NOT, "affected");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS/Model");
  if (model !~ "3750[Xx]") audit(AUDIT_HOST_NOT, "affected");
}

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
  flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_switch_service-modules", "show switch service-modules", 1);
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"\s+\d+\s+OK\s+", string:buf)) { flag = 1; }
    }
    else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : CSCue92286' +
    '\n    Installed release : ' + version + '\n';

  security_warning(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
