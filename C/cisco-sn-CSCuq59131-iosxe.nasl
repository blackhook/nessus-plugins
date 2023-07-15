#TRUSTED 374deebf131362bcec7988ff27e5ba4c02ace10519ee8a084cd1a0126ffb3b289bf657bf7bc445b7577692c9466e3dc2790453d8e7a6439f7273145aee51ac17292d3e4f1270849a0999edebe90347d0280b9eaab459ea45954c1c79a3ab9105a21bc6d9a046870d1ab0159935caeb29ab5101180f2bde00224f2ad3e2086d9691eec2470e29eef55f8ef2d443ab59acde0f1a2cabc8fbe8d6caec356d758ad7779da07475eb7b6ac2a92b9b044c60eef8456fd8014d414284994cf496164781c87dc49f9be3cb15a0489cde090714896292acb6a39b87d913fdd2d068a2a95d2ee62a36fd164b94481eeb6f3bb6f4f04d534eedb4f425b2e622a5bbf23d789f491b17dd68884ac28d80a190f45e4dd3096fcc4c8ea20986e982ce4c56342637d1bbedc5dd1560166acbff9f256c29d62e8b4d91333aec6d505d87feddb83346e26d2499e0b58217b20d5141af32ec47bd99cb9c27f5a17c1a653fa5540585be7d5e646e477bc5001cf16ece357477125574bcc0dddeeaeadf8131e4bd6e9e0f0d4a039e8927fd529f174b07e69103bcbd1c146a658c448b4990173d9adbbac04f8924ea891c487e36bb87d82b38e848d8414800a6d323aa596ecdf4a8177fefc8d43d5180592a80b2c95d705ac6d6937e5ff29663ef769852caab03148814099d17d84e5b1fabb77b5de8450661a31c26cf64f644e2dc83da52a0675ca6c0d0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82590);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0645");
  script_bugtraq_id(73337);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq59131");

  script_name(english:"Cisco IOS XE Layer 4 Redirect DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability due to improper processing of IP
packets by the Layer 4 Redirect (L4R) feature. An unauthenticated,
remote attacker, using crafted IPv4 or IPv6 packets, can exploit this
to cause a device reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cbb5bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuq59131");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");
if ("ASR" >!< model &&
    "ISR" >!< model &&
    "CSR" >!< model
  ) audit(AUDIT_HOST_NOT, "a ASR / ISR / CSR device");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Bug
if (version == "15.2(4)S0.1") flag++; # Not in map

# CVRF
if (version == "3.1.0S")   flag++;
if (version == "3.1.1S")   flag++;
if (version == "3.1.2S")   flag++;
if (version == "3.1.3S")   flag++;
if (version == "3.1.4S")   flag++;
if (version == "3.1.5S")   flag++;
if (version == "3.1.6S")   flag++;
if (version == "3.10.0S")  flag++;
if (version == "3.10.0aS") flag++;
if (version == "3.10.1S")  flag++;
if (version == "3.10.2S")  flag++;
if (version == "3.10.3S")  flag++;
if (version == "3.11.0S")  flag++;
if (version == "3.11.1S")  flag++;
if (version == "3.11.2S")  flag++;
if (version == "3.12.0S")  flag++;
if (version == "3.12.1S")  flag++;
if (version == "3.13.0S")  flag++;
if (version == "3.2.0S")   flag++;
if (version == "3.2.1S")   flag++;
if (version == "3.2.2S")   flag++;
if (version == "3.2.3S")   flag++;
if (version == "3.3.0S")   flag++;
if (version == "3.3.1S")   flag++;
if (version == "3.3.2S")   flag++;
if (version == "3.4.0S")   flag++;
if (version == "3.4.1S")   flag++;
if (version == "3.4.2S")   flag++;
if (version == "3.4.3S")   flag++;
if (version == "3.4.4S")   flag++;
if (version == "3.4.5S")   flag++;
if (version == "3.4.6S")   flag++;
if (version == "3.5.0S")   flag++;
if (version == "3.5.1S")   flag++;
if (version == "3.5.2S")   flag++;
if (version == "3.6.0S")   flag++;
if (version == "3.6.1S")   flag++;
if (version == "3.6.2S")   flag++;

# From SA (and not covered by Bug or CVRF)
if (version =~ "^2\.") flag++;
if (version =~ "^3\.[789]($|[^0-9])") flag++;

# Check L4 Redirect config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^\s+redirect server-group ", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^\s+redirect to group ", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCuq59131' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
