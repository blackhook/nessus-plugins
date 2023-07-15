#TRUSTED 3ff1a94914d83cc5ffcf84276c0c305c99f8b0be6174b8d04d570d817cf59c4c696f69a5e85450548ecdb8376df629d7df3f04b9a08d1959c534efc15a862dcc6a9b38cfa12d5f5ed7f89220a63ae6e82bf7939fa7ec64c0ba314ae65bdbe1bda25265935c43f9f9d2f4952e2c50ff3f3bafe5cad13f3ce22fe21b079d3addf4d2df66057fc6a92cf4d0e7bee34af3b5b05d7741f2ee77abf0ed40d54cda2e343db878fd20de4c80fd32dfcddb2b4770053fb6c3fba138d131e8bc427d36f12ed9d65b13766055adb7ab555ed237130328dadade7be4682e465a6a3aa2d7ce6be2fd71f6cf7b85c94b481564bc6cbb01d7d4b0ba7ef86265ba4fd793dd4d48445252b53dd00388c3232430d441ae2ace5f4cc916d49c9885a8150229ad55140f3e25c2a4f8e5e48a1444a41d5686eef5e91911769bd4c4063a650a26efc9204eeb0edc68296689d470d14555c813892a96aa4c37269aef3b1789b4e82939a29d480ac5c7c344a93f7ee9855930083d38c5056a0a30e16561815c7322d8838ae842915751db0f4ce23bd3551dfd590a3351de078b041485df3eeb1cd9e9fa970f688561d339dd8111132a143a070eb111fdd9033a70db69d1395a335c36bc1fcc187c0b40c4ff45c29ddc63b3cac9815465d7d7a474d031db8183b3654b17bf4e2df949f5ba7d0a5869f4dbaf48d8cf27d6d6fdc48cee20e137599fad23d818e0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76790);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3284");
  script_bugtraq_id(67603);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo55180");

  script_name(english:"Cisco IOS XE PPPoE Packet DoS (CSCuo55180)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
affected by a denial of service vulnerability.

The issue is due to improper processing of malformed PPPoE packets. A
remote attacker, with a specially crafted PPPoE packet, could cause
the device to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34346");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34346
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e780a5c3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuo55180.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");


version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model = '';

if (get_kb_item("Host/local_checks_enabled"))
{
  # this advisory only addresses CISCO ASR 1000 series
  buf = cisco_command_kb_item("Host/Cisco/Config/show_platform", "show platform");
  if (buf)
  {
    match = eregmatch(pattern:"Chassis type:\s+ASR([^ ]+)", string:buf);
    if (!isnull(match)) model = match[1];
  }
}
if (model !~ '^10[0-9][0-9]') audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

flag = 0;

if (version == '3.7.0S') flag++;
if (version == '3.7.1S') flag++;
if (version == '3.7.2S') flag++;

# Check to see if PPPoE is actually enabled on the host
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ( (preg(multiline:TRUE, pattern:"pppoe enable", string:buf)) && (preg(multiline:TRUE, pattern:"ipv6 address", string:buf)) ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco Bug ID      : CSCuo55180' +
    '\n  Installed release : ' + version;
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
