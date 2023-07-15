#TRUSTED 7d535489fa984f46e13678ad50b60e2f58d467a8196a6f8637f176cda2c2a3c7c8fcb8b50d73d4afc727eb9e815d9fdcbd66b525872e305e287c87fd7839aaa8094d8654884e0e9414e8675e0444a3886f1d817e3e8531bae9053afb6119ebf36b39738ab495953fff5fb51eb2cca9c9e3dae246f41a833fd3c322cca7c05f78cb5573d3eb273ffe65642a5e5d6f52a1dc3b1177d9124a0a8019a7c12313cb35fdc04ccaabfe851a346dfd2194b558dea45a98823911f6b4a8a00cb23de196ebec84b0e868e5c226dbbb72bde1331b0b848cae35127636beef20230a470414213896f59127a995585a8c9119c4bf68d39b38b338273438432166c434394b5f039df7fa0c3a492a8516b1c4303e0a127689f4f9871cf8b5732fcbe6b15a65e6e46b53170490c486e2fd54cd8f87bbb6e82a167f9d4e41577ca1d13a91b20a493191826aa5a219714eafcd0c440a34cfae44bf379e88f688992b0cc209f03fe32849fe523154c4d1e5a8500b75a96f7f355a730d12bd9df5a6a47792e127f63b9a2a0c20ad8c041b6c23e90b207ff48ac6dce75721836f913a82cbc5c9907667e879f31f19f90d272077324d12b82e51de6db6574f417286c0111d71730d9933c93e22232107944ef895330bfaff63873e023240b6722d70d11da8a8bda3b7a00dc26c59da1990821869ca0b6ef0cc8e4f1c9acec0e432c249f889af15294fa7be
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74036);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-2182");
  script_bugtraq_id(67100);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun45520");

  script_name(english:"Cisco ASA DHCPv6 Relay DoS (CSCun45520)");
  script_summary(english:"Checks ASA version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Cisco ASA device is
affected by a denial of service vulnerability due to improper
validation of packets when the IPv6 for DHCP (DHCPv6) relay feature is
enabled. An unauthenticated attacker on an adjacent network could
cause a denial of service by sending a specially crafted DHCP packet.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=33980
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb540273");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=33980
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb540273");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug Id CSCun45520.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9](|-)X($|[^0-9])')
  audit(AUDIT_HOST_NOT, 'ASA 5500-X');

fixed_ver = NULL;

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.8)"))
  fixed_ver = "9.0(4)8";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.2)"))
  fixed_ver = "9.1(5)2";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if DHCPv6 relay feature is enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"ipv6 dhcprelay server", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the DHCPv6 relay feature is not enabled.");
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
