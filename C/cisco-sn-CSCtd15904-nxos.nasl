#TRUSTED aa6f0c553d929f0c699139986e4df79a2265eaf7317eda671af7e62a95f6ac38d2bbe0d5b7e5d6e8e0f9fb58a60e43e24fe38b79d440511c6b68024af5ab9675754fe2d513f56ff398be51b3122387aa280ddb2739e115c3edb4481648291dbf549778a8f8bc73e83110930613c4baf5f7b4e64f7047e20e975633ed954315d81c7951e6a106e269996c4f54fbdf48b1c587827fd7e515fa8e944c9e103748bdaeb606d046c26acc246c3e8f1a6720bc7d384c670270686477b5965fd633ad4893c09d8005be472d64885fb301d93204a9662368fc7a4dcfaf7344d653855d4cee00aa92c2d91ffa0239545409a880aa235716a7b57ee1e6b2e64f0d61efd5103af3f645e7625b94b347a6125950cf2f680363e19b0f53d7563a3195f5f8470a4b49b313db952cfb6b6631a0ae78e20b68e31cb65ac6cff8c5fc70f58cfd8b957ae8de77fd65bac9e7c743d2c8d67493c96edd1090da14dba258976797e8c8621e13748da6f1fe4a7365ae6364dc141e5c94f7b383a4c64fe5fa782482ee8b8783eef53a71ca67aca84a44915443a04dae9c3e5b7cb49e70d1577efd13a2129a8f11b50bcecf8bd1a4d84df894ffaf518025d3289832587759e086af48668f4ae9b2eaecdc8a5aeb0beccf68b58f7a54c422efc9da865f857ec2c523d1decd902f6335748e6236243beaf8cad85cf4da715b365ac47ee52cb9c8d37afed75d0d
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was extracted from Cisco
# Security Notice CVE-2013-6683.  The text itself is copyright (C)
# Cisco.
#

include("compat.inc");

if (description)
{
  script_id(71153);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/10/29");

  script_cve_id("CVE-2013-6683");
  script_bugtraq_id(63685);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtd15904");

  script_name(english:"Cisco Nexus 4000 Series Switches IPv6 Denial of Service (CSCtd15904)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the IP version 6 (IPv6) packet handling routine of
Cisco NX-OS Software could allow an unauthenticated, adjacent attacker
to cause a device to stop responding to neighbor solicitation (NS)
requests, causing a limited denial of service (DoS) condition.

The vulnerability is due to improper processing of adjacencies in the
IPv6 neighbor table. An attacker could exploit this vulnerability by
sending a sequence of malformed IPv6 packets to an affected device. An
exploit could allow the attacker to cause a device to stop responding
to NS requests, causing a limited DoS condition.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31740
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba5584b5");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in Cisco bug ID CSCtd15904.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2019 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version","Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# only affects nexus 4000 series systems
if (device != 'Nexus' || model !~ '^4[0-9][0-9][0-9]([^0-9]|$)') audit(AUDIT_HOST_NOT, "affected");

flag = 0;
override = 0;

if (version =~ "^4\.1\(2\)E1\(1[bdefghij]?\)") flag = 1;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"IPv6\s+is\s+enabled", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  if(report_verbosity > 0)
  {
    report +=
      '\n  Cisco bug ID      : CSCtd15904' +
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
