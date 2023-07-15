#TRUSTED 6c5d58983368d7ccf631ae3168717d3c31d3650e93f686369b2bc651229c1a5268ff37235dd6d940ef34808ed715f7933d70d4ae7e44ca3e74c6ab310a3e520d85af8e88714ed3c75382e44de3a60def9a7238b2ffbf4b6b0fb887c586c0777b07a14fb681aacc736acea6348d8d7a5ef4a5e0b3dd15338129da107d8b0f873e0563add88e83c2296c664985a1cef566bb50d4379f3d10f5aa2d8c635eef3fb828a7a79543bc42e37c2c4d2bf212efc336cb532f2c5338601637cb22da09815c81664fcb94b0629fbb2e2f35d75d19a79b77d08e87dd6bcdc7b61fb333244381902ebc0e41ee8550a5426ae0c29b523d530fa762037b2a0d30354e81c1d20018bbae936cc7e3458e93278a863f203a735e3c7fa13bb8595f0ecd31051ec481812b481de9a65625f37dc1003a914aeb5ae82ca61b4a6b4456a87798977399dfac3187416c996e7f35a4b2bc5ac058f304e0317032b15931a8975df10df9686a581a97d8dad5a73be3e9c65d7e6a55ebc6c74b398b4d35a1c548b25b60c8e39fd7aa0bb3f82460bb033c6496bf3fa42d1a1e7f6c913e14f53fb66acfc41392adfe67063f93c8bbc629f3dacca2ab0b23ca58f3da004e34d444513bd67bab974bf959c87b11be1998ff8d7440710f52f023ccbfd911312bdf5d79a63fedf688fa50f8cf3bb2f0b798f0da2a69df796b795b6ed63771f99288fb1bc255844067e1ef
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76312);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2014-2176");
  script_bugtraq_id(68005);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun71928");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140611-ipv6");

  script_name(english:"Cisco IOS XR Software IPv6 Malformed Packet DoS (cisco-sa-20140611-ipv6)");
  script_summary(english:"Checks the IOS XR version.");
  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XR
running on the remote host is affected by a denial of service
vulnerability due to the improper handling of IPv6 packets. A remote,
unauthenticated attacker can cause the device to lock up by rapidly
sending specially crafted IPv6 packets.

Note that this issue only affects Trident-based line cards on Cisco
ASR 9000 series routers. Also, if IPv6 is not enabled, the device can
still be exploited by a host on an adjacent network.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140611-ipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28457895");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33902");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140611-ipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# check model
model = get_kb_item("CISCO/model");
if (!isnull(model) && model !~ "ciscoASR9[0-9]{3}")
  audit(AUDIT_HOST_NOT, "affected");
else if (isnull(model))
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_HOST_NOT, "affected");
}

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

# Patches are available for the versions below
if (
  report_paranoia < 2 &&
  (
    version == "4.1.2" || version == "4.2.1" || version == "4.2.3" ||
    version == "4.3.1" || version == "4.3.2" || version == "4.3.4" ||
    version == "5.1.1"
  )
) audit(AUDIT_PARANOID);

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

flag = 0;

if ( version =~ "^3\.[79]\.[0-3]$" ) flag++;
else if ( version =~ "^3\.8\.[0-4]$" ) flag++;
else if ( version =~ "^4\.0\.[0-4]$" ) flag++;
else if ( version =~ "^4\.1\.[0-2]$" ) flag++;
else if ( version =~ "^4\.2\.[0-4]$" ) flag++;
else if ( version =~ "^4\.3\.[0-4]$" ) flag++;
else if ( version =~ "^5\.1\.[01]$" ) flag++;

if (!flag) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

flag     = FALSE;
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_diag", "show diag");
  if (check_cisco_result(buf))
  {
    pat = "A9K-(40GE-L|40GE-B|40GE-E|4T-L|4T-B|4T-E|8T/4-L|8T/4-B|8T/4-E|2T20GE-L|2T20GE-B|2T20GE-E|8T-L|8T-B|8T-E|16T/8-B)";
    if (preg(multiline:TRUE, pattern:pat, string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco Bug ID      : CSCun71928' +
    '\n  Installed release : ' + version +
    '\n';
  security_hole(port:port, extra:report+cisco_caveat(override));
}
else security_hole(port:port, extra:cisco_caveat(override));
