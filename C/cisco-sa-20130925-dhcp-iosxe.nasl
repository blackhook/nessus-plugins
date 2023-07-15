#TRUSTED 1a46586e503bd00547c1d5fa47c9a57239d44a0befdec866c65aa398e66a0c44f148d3f82ce2b758dee0743db8655bebac1dc2884cf11a05c9363c9b3885dce69340b50cea32d0d62a69d0b0d02977f96404e6c0f972163c1ebc9210a0d788f18dddfebc1b1f86f2d13ba458dfbf077a5fcc2d2d47c31a6ca0321d210b82986082769330b1c76b7723c44f3948b19ac2c4635bad5b9b45b060ab066c12d9d73b77c798698a56e035893c8e08cfa8c0b426d1e75879e959d28b4eecc719a9ce0fce0f289cdacc6beb163b61205c6f6075fee09de4beb0c593fee5458b75c2872fbf59d11f38ee93e4f479128eff5ae808ad74c3c57b6ca3f964876865f13b6cfd5135d8e82b47f057d8681d3b6a6138ed381b8884e35f325b2d8c81cb292c7f8c3fde20de4686425272fd0d4400e2e4e2ed214e29bd59f81ae883db5de7b0660306fc6e5f590341d0687a1dca643101ab115590e192643fbcd928359acf26c8e8a13fced7b2de228b354cac61a8c85eb4ddbfd960fd945c35718d9b148821dde4781c14d52242221215fecfd9e14a5cdb5623ed92ff50e79f2889e63a38ae5892d955be7f2db4e99a3dd6e1bdfad2f3fb2f1d1670d61ae5519c05d846ef22a994c8942a5740406420ddb31d55ae18f1ab220849e5c56c532b3e6a3706f3d4f9af8b5f23183c20e699f551b336b871e89ca2095e1d5984b8b8fcad7fdc2843ba89
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-dhcp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70315);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5475");
  script_bugtraq_id(62644);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug31561");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-dhcp");

  script_name(english:"Cisco IOS XE Software DHCP Denial of Service Vulnerability (cisco-sa-20130925-dhcp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the DHCP implementation of Cisco IOS XE Software
allows an unauthenticated, remote attacker to cause a denial of
service (DoS) condition. The vulnerability occurs during the parsing
of crafted DHCP packets. An attacker can exploit this vulnerability by
sending crafted DHCP packets to an affected device that has the DHCP
server or DHCP relay feature enabled. An exploit allows the attacker
to cause a reload of an affected device. Cisco has released free
software updates that address this vulnerability. There are no
workarounds to mitigate this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-dhcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6378bd7b");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130925-dhcp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
if(version =~ '^2\\.1([^0-9]|$)') flag++;
else if(version =~ '^2\\.2([^0-9]|$)') flag++;
else if(version =~ '^2\\.3([^0-9]|$)') flag++;
else if(version =~ '^2\\.4([^0-9]|$)') flag++;
else if(version =~ '^2\\.5([^0-9]|$)') flag++;
else if(version =~ '^2\\.6([^0-9]|$)') flag++;
else if(version =~ '^3\\.1(\\.[0-9]+)?S$') flag++;
else if(version =~ '^3\\.1(\\.[0-9]+)?SG$') flag++;
else if(version =~ '^3\\.2(\\.[0-9]+)?S$') flag++;
else if((version =~ '^3\\.2(\\.[0-9]+)?SE$') && (cisco_gen_ver_compare(a:version,b:'3.2.3SE') == -1)) flag++;
else if(version =~ '^3\\.2(\\.[0-9]+)?SG$') flag++;
else if(version =~ '^3\\.2(\\.[0-9]+)?XO$') flag++;
else if(version =~ '^3\\.3(\\.[0-9]+)?S$') flag++;
else if(version =~ '^3\\.3(\\.[0-9]+)?SG$') flag++;
else if((version =~ '^3\\.4(\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.4.6S') == -1)) flag++;
else if((version =~ '^3\\.4(\\.[0-9]+)?SG$') && (cisco_gen_ver_compare(a:version,b:'3.4.1SG') == -1)) flag++;
else if(version =~ '^3\\.5(\\.[0-9]+)?S$') flag++;
else if(version =~ '^3\\.6(\\.[0-9]+)?S$') flag++;
else if((version =~ '^3\\.7(\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.7.2tS') == -1)) flag++;
else if(version =~ '^3\\.8(\\.[0-9]+)?S$') flag++;
else if((version =~ '^3\\.9(\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.9.2S') == -1)) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
  flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_dhcp_pool", "show ip dhcp pool");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"[Aa]ddresses", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip helper-address", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"ip dhcp pool", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
