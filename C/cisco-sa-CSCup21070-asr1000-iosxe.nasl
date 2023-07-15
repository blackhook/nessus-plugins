#TRUSTED 08a015db63b3f0ae7aa503c4036f71e2fb85111eeb7010c30f5bcbe1e2e1127c5c568c68a0043742a1c6d1add1ec3e9728efed462eae400d6e647b729bac789f6eeb5d3c760de33c1ea22ea6c509955fbdcd1478bfe0edbb9ab433c14ebd7f49402b5920e0833cfae09ba83cc3977ff521db5df5890ef9c3cf41ebc5ded1b1eb9e575dfe16f6b5072a88a2d8530ef385afce69beb3c26a0d213da4dbe2fe17589e61268dd59be377bb83cc99379c2eea4fdc5eef4f248df5af1af70f010f774134776eb110331844f093207347032be38323447242e2a8752f7f75aa7e11fafd4e15db845cc1fe25c0f094fea82e58d7733e542de22c417b002724117e14a642042d1ae684a70494f0507837fbaa01b3830aed358c5110f82c28e1486f056be02ab01e1729dc90345808bd020748bb6308139bd70933be56fbca2dd96fe0ecea948ba485c5243963a13e8f3ed4f6706844cf07b8d2dc74ba2e80e7a648c5ff972bc3a5296d2de7bc280c16b5813f11dfeeae4e7078e7c46b716325d5cfb934a7b4543db581b0e88582cc987d089316db1e8d5b7cf43ff9b0b15548f6885a71f6701d64d568ca434e5ce8c6b574c7e0b6a9c0d856bb3515456979e8816486213e7f166259a439175f00d2e15c9ee28f6627e202c3a3cdd61d69810bd6383540fa44ee6e50457047c78990087a274a8994f39bdd7ca583f75774e8d8ca8f8c0b51
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83871);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0688");
  script_bugtraq_id(73914);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup21070");

  script_name(english:"Cisco IOS XE Software for 1000 Series Aggregation Services Routers H.323 DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS XE Software for 1000 Series Aggregation Services Routers
(ASR) is affected by a flaw in the Embedded Services Processor (ESP)
due to improper handling of malformed H.323 packets when the device is
configured to use Network Address Translation (NAT). An
unauthenticated, remote attacker by sending malformed H.323 packets,
can exploit this vulnerability to cause a denial of service by
crashing the ESP module.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38210");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant version referenced in Cisco bug ID CSCup21070.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
model = "";

# check hardware
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
if (model !~ '^10[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

cbi       = "CSCup21070";
fixed_ver = "";
flag      = 0;

if (version != "3.10.2S")
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", version);
else
{
  fixed_ver = "3.10.4S";
  flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_nat_statistics", "show ip nat statistics");
    if (check_cisco_result(buf))
    {
      if (
           (preg(multiline:TRUE, pattern:"Total active translations:", string:buf)) &&
           (preg(multiline:TRUE, pattern:"Outside interfaces:", string:buf)) &&
           (preg(multiline:TRUE, pattern:"Inside interfaces:", string:buf))
         ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report = "";

  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : ' + cbi +
      '\n  Installed release : ' + version +
      '\n  Fixed release     : ' + fixed_ver + '\n';
  }
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
