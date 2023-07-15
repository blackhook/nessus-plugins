#TRUSTED 0071eb61fb6315fb08000cf791db639a389f07960ed9b6b0a59eadb75b6f3b2a43d5fb685264018d5a76a23958000399aea4544b0fbc7dd8b263ad20b803be28e566efc0cb6cb7b3a703d5a72feeb4564de7fa686936ecff67e5f76b2c39daf06ad5027c353e7b8d45290acbe851d5e2517cd50c53d8579cb0673fac19e43bb22d024ff3e0b0eafa9aebdcd8e38a8efa78308ed0eb2812b879be9e775a5c11e956e2af23287c066cfb664efa439d3e36e3fec92936c24d5045f5a390ccc002f93d2ab8e3328de914bbd91e537a26019a450241b1d320a79130cf4016371f48f31cc4af86fb0a95ab0dd05cf476349cdb6e8c3542c24b0437a1ff97cd6138f49498c59d3e78d935405d858afe00c9d4a979596051c6b7f9781bba954c977243bed7e87fb76a137566435ee54136f82ef1145963650ab364e86866a02d3b9d222a2370d00c42e085ef69cf7d1efd3827652a8e761821dda2d82b53abfdfa455d3ef202ba498e652892215acc69b2e16eb8dccc52fb0ca68446e34b9c6967859a2e3877fa69f1b03459cb3f780b686109b6a1fafffb4ccaccb75f4cc9473cad68d84aa2c5be8bbfa63afaf8e62b86d5a0f49417b2b9544fac238395448c432b468849cf51c524904a3fe33826e6adcf203151cc2d28a8a117d9a1e228f7228c8dcb7d41ed10b1767ab292f5a62d6136c940cac022a8c4d788a90073e774aa856fda
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95256);
  script_version("1.12");
  script_cvs_date("Date: 2020/01/16");

  script_cve_id("CVE-2015-6392");
  script_bugtraq_id(93406);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq24603");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur93159");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus21693");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut76171");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161005-dhcp1");

  script_name(english:"Cisco NX-OS DHCPv4 Crafted Packet DoS (cisco-sa-20161005-dhcp1)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco NX-OS software
running on the remote device is affected by a denial of service
vulnerability in the DHCPv4 relay agent and smart relay agent due to
improper validation of DHCPv4 packets. An unauthenticated, remote
attacker can exploit this, via a specially crafted DHCPv4 packet, to
cause the affected device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-dhcp1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f80fa40");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20161005-dhcp1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# Only affects Nexus
if (device != 'Nexus')
  audit(AUDIT_HOST_NOT, "affected");

flag = 0;
override = 0;
fix = NULL;

########################################
# Model 5000
########################################
if (model =~ "^50[0-9][0-9]([^0-9]|$)")
{
  if (version =~ "^([0-4]|5\.[0-2])([^0-9])")
    fix = "5.2(1)N1(9)";
}
########################################
# Models 2k, 5500, 5600, 6k
########################################
else if (model =~ "^([26][0-9]|5[56][0-9]?)[0-9][0-9]([^0-9]|$)")
{
  if (version =~ "^([0-4]|5\.[0-2])([^0-9])")
    fix = "5.2(1)N1(9)";
  else if (version =~ "^6\.0([^0-9])")
    fix = "6.0(2)N2(7)";
  else if (version =~ "^7\.0([^0-9])")
    fix = "7.0(6)N1(1)";
  else if (version =~ "^7\.1([^0-9])")
    fix = "7.1(1)N1(1)";
  else if (version =~ "^7\.2([^0-9])")
    fix = "7.2(0)N1(1)";
  else if (version =~ "^7\.3([^0-9])")
    fix = "7.3(0)N1(1)";
}
########################################
# Model 7k
########################################
else if (model =~ "^7[0-9][0-9][0-9]([^0-9]|$)")
{
  if (version =~ "^[0-6]\.")
    fix = "6.2(16)";
  else if (version =~ "^7\.2([^0-9])")
    fix = "7.2(0)D1(1)";
  else if (version =~ "^7\.3([^0-9])")
    fix = "7.3(0)D1(1)";
}
########################################
# Model 9k
########################################
else if (model =~ "^9[0-9][0-9][0-9]([^0-9]|$)")
{
  if (version =~ "^(6\.1|7\.0)([^0-9]|$)")
    fix = "7.0(3)I1(1)";
  else if (version =~ "^11\.")
    fix = "11.1(1)";
}
else audit(AUDIT_HOST_NOT, "an affected model");

# Check if version is below the fix available
if (!isnull(fix) && cisco_gen_ver_compare(a:version, b:fix) < 0)
  flag = TRUE;
else audit(AUDIT_HOST_NOT, "an affected NXOS release");

# Check for DHCP configured
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_dhcp", "show running | include dhcp");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"^\s*ip dhcp relay", multiline:TRUE, string:buf)) { flag = TRUE; }
      else audit(AUDIT_HOST_NOT, "affected due to vulnerable feature not enabled");
    }
    else if (cisco_needs_enable(buf)) { flag = TRUE; override = TRUE; }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    version  : version,
    bug_id   : "CSCuq24603, CSCur93159, CSCus21693, CSCut76171",
    override : override
  );
}
else audit(AUDIT_HOST_NOT, "affected");
