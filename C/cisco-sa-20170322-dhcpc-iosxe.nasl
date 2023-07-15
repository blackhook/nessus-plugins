#TRUSTED 5bdbb4b53aedf7a28951a749cb4446bfa59be1d703948650b0035dcbef9d1db15cb7950f15d18bb541768ff1f447b6938909805598f516cd6c44d9a18722cd08b14a6f184465ab473c64f54c891dd27b7198b354ca42bc8f013cba1967c75dbc567fe7bdbc6a62d184121e732a818145d7e430745bbac78ed289d2622308df4674f9929880ef7f75c18831eba624d6791b07e9e452f1dfca7f98246cf9280f54d6b44200a392a93ba0e51d149f29487bab04ae88e4fc765f5a4db876e110b8a94c9cbcb15c8962745f5eefec70ac1a56dae857d94ce414f0f7cc707233f432d24dd8bb64b531b546f256effc13bb5e5b6d409f93ae41d0413363d5fb3f69812eaa63956be534e4c6db2a5d77fe44c926a141cda7bf44f003c324a406b8e37d46be8be2ebd6de8d96fb06028bc0335a082aabc0ce447678e49947b0e816dbdb302c716448501ab04c483e04bb9fe94b54c5e84a0e63ec98aab6200913899f953eedb4c02621df1e9418bdba989f538fcdf78ec7ea342e67bf307fbbfd0817ab028cfa8aa51a9f800b71ca5843af4642dc66e8dff53c6cf41b9087c0c170a6e9883309ef476cc8cedfafcc5a4d3e571a8ae1a8830297f45fa1f294895fd2313886457d97a6b0d2b37d5acc8a5dd07a9cd0f6215fefa40c85d1488e2627f0af14f2a6b812a18592bbdcd516f176435ad52626512deb092d96e8274c94c2e621399b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99027);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3864");
  script_bugtraq_id(97012);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu43892");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-dhcpc");

  script_name(english:"Cisco IOS XE DHCP Client DoS (cisco-sa-20170322-dhcpc)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the DHCP client implementation when parsing DHCP
packets. An unauthenticated, remote attacker can exploit this issue,
via specially crafted DHCP packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-dhcpc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d54a2ce");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu43892");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuu43892.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;

if (
  ver == '3.3.0SE' ||
  ver == '3.3.0XO' ||
  ver == '3.3.1SE' ||
  ver == '3.3.1XO' ||
  ver == '3.3.2SE' ||
  ver == '3.3.2XO' ||
  ver == '3.3.3SE' ||
  ver == '3.3.4SE' ||
  ver == '3.3.5SE' ||
  ver == '3.5.0E' ||
  ver == '3.5.1E' ||
  ver == '3.5.2E' ||
  ver == '3.5.3E' ||
  ver == '3.6.0E' ||
  ver == '3.6.1E' ||
  ver == '3.6.2aE' ||
  ver == '3.6.2E' ||
  ver == '3.6.3E' ||
  ver == '3.6.4E' ||
  ver == '3.7.0E' ||
  ver == '3.7.1E' ||
  ver == '3.7.2E' ||
  ver == '3.7.3E'
)
{
  flag++;
}

cmds = make_list();
# Check that device is configured as a DHCP client
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include dhcp", "show running-config | include dhcp");
  if (check_cisco_result(buf))
  {
    if ("ip address dhcp" >< buf)
    {
      cmds = make_list(cmds, "show running-config | include dhcp");
      # Check if device is configured as a DHCP server or DHCP relay agent
      buf2 =  cisco_command_kb_item("Host/Cisco/Config/show running-config | include helper|(ip dhcp pool)", "show running-config | include helper|(ip dhcp pool)");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"ip helper-address [0-9\.]+", string:buf2))
        {
          cmds = make_list(cmds,"show running-config | include helper|(ip dhcp pool)");
          # Check if device is configured to send DHCP Inform/Discover messages
          # If device is confiured to send DHCP Inform and Discover messages
          # then not vuln
          buf3 = cisco_command_kb_item("Host/Cisco/Config/show running-config | include (ip dhcp-client network-discovery)", "show running-config | include (ip dhcp-client network-discovery)");
          if (check_cisco_result(buf3))
          {
            if (preg(multiline:TRUE, pattern:"ip dhcp-client network-discovery informs .* discovers .*", string:buf3))
            {
              flag = 0;
            }
            else
            {
              flag = 1;
              cmds = make_list(cmds,"show running-config | include (ip dhcp-client network-discovery)");
            }
          }
        }
      }
    }
  }
  else if (cisco_needs_enable(buf))
    override = 1;

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCuu43892",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
