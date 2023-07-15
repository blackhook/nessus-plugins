#TRUSTED 7d0422f30bb3b354ba29fdd88077ab6644e0bb8fa3a36196a80b774687e6c7c5a825c79951a753fd4df8998f15dc648a39e1356af27c40be3fafb7cb85226a7af0c477e4f82e76e50f83fb330d2a82680f4b8e7c1c185399bb8817713db9ffd9200e78c3dc30886571c8562a957b6b1a3636c5a5febfc433817bd8ad261891aa7e8667baec585ef6245fd4242a5d5d2983a9f26a404273bada83ccd51aa25804c1c41570c31fee156b53a8d6a38983336ba060542c2a128d56d5e51d8df68062c7cfe500cedffffd5701566b598f6c1f3b568b4d6f86fc604f9dcbf95e495ee26d7196de97a7b6d3c1222d8cf832c5253fe0328460ce6540ec6eb7d9afad9666b5980812be339b878f7663e69c20b963b1227a8439d8eaaba307a31eaf3720e2f1c19021392d9e6104b07e8b482898e79ccfb53f2e484ea4ed4064406f2b6e1ec82a14d62d216fb38b2dee38f052d8ecbb8c901948144bbcbd966b9472d4aa6fe9a84c5c6e8acf18effcaad7bfb4c4283a36f759928d3a01ad4d8935336d3ea264f700f2f860bc27b72fdf1ade3a386adffc32da6679c61ce214c1d360bf27c122909a7c05411d23c4bb6485d1dd4561402017bdc29c92588d4becf045479c8d15304c5fb817764e9edf2397aa29437f3cc5164950517578fe5f1a2f8e85f30ae08ae8e8187150e24c6f033e11d6d761b65d904430c6b91386d8b48f9f866962
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95257);
  script_version("1.12");
  script_cvs_date("Date: 2020/01/16");

  script_cve_id("CVE-2015-6393");
  script_bugtraq_id(93419);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq39250");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus21733");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus21739");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut76171");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux67182");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161005-dhcp2");

  script_name(english:"Cisco NX-OS DHCPv4 Crafted Packet DoS (cisco-sa-20161005-dhcp2)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco NX-OS software
running on the remote device is affected by a denial of service
vulnerability in the DHCPv4 relay agent due to improper validation of
DHCPv4 packets. An unauthenticated, remote attacker can exploit this,
via a specially crafted DHCPv4 packet, to cause the affected device to
reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-dhcp2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20f16ba1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20161005-dhcp2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6393");

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
  else if (version =~ "^6\.0")
    fix = "6.0(2)N2(7)";
  else if (version =~ "^7\.0")
    fix = "7.0(6)N1(1)";
  else if (version =~ "^7\.1")
    fix = "7.1(1)N1(1)";
  else if (version =~ "^7\.2")
    fix = "7.2(0)N1(1)";
  else if (version =~ "^7\.3")
    fix = "7.3(0)N1(1)";
}
########################################
# Model 3k
########################################
else if (model =~ "^3[0-9][0-9][0-9][0-9]?([^0-9]|$)")
{
  if (model =~ "^35[0-9][0-9]([^0-9]|$)")
    fix = "6.0(2)A6(6)";
  else if (version =~ "^[0-6]([^0-9])")
    fix = "6.0(2)U6(6)";
  else if (version =~ "^7\.0([^0-9])")
    fix = "7.0(3)I2(2b)";
}
########################################
# Model 7k
########################################
else if (model =~ "^7[0-9][0-9][0-9]([^0-9]|$)")
{
  if (version =~ "^[0-6]([^0-9])")
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
    fix = "7.0(3)I2(2b)";
  else if (version =~ "^11\.")
    fix = "11.1";
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
    bug_id   : "CSCuq39250, CSCus21733, CSCus21739, CSCut76171, CSCux67182",
    override : override
  );
}
else audit(AUDIT_HOST_NOT, "affected");
