#TRUSTED 45c444ab6a512134e0f72f568bea66bbf6656f634af78ccc345cfe4bea20ee00f990c758796e4fb4e34aa3608d111f5b94ff4a5303b5cf0673802953ab179603417970f25046e86a6dd81e88b606052c54b54763c90430f313a61b6bacaa9948ed9b7d46c2ea3bb32eb637a8fe94ae1dfdc56f5dabf246849eb10a996593e0cf0a88242e47c827ad656ae10cd6e88b1779785b3969165d420c3a82911c0a2ea6cc08b87eb5c0acbb1015fda1cf78a17130b17b409b43374304ccd832909161dcf556d3fee80897cc15f82d383777b2e4d23f4576aa013ac5b912dc697cbc1698fc86032f394260cfd1254729685eb94f91c9e8416bfa0ffbb94c5f0357c4ba79bc43c0d082474f4ef98ad208e593f97dd76790d86290b21c45d7764e03a15b7bd14ff8d2b14a203e185e63bf93281cce6795cfd550ff576199ab60313d2e4ab310d8b758e956450c0db3a9bfa61966fd25a1e4a8c8a22561422659e484e1e3eccf6e170bf0439791dc87ec42a14c8c8ccf1b5ae1187bd40ea2d2e51179c6b6d9e4ced194915283644dff2bddf98b2e7ed2000bb870a00759a49e514c2dc8919d99699cea9cfe17abc1ca3af63971689c5fa29bfccc0c5914109cc63cff60c4d7fcb1290ee147ebe78be9e14bf9e113069686b457b07e5b731843e3690a5c33002c7585974f2e36901dc57bc90624fd2a304f2a5a8f9aa6f3886fcd6d25b4432f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83054);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2015-0695");
  script_bugtraq_id(74162);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150415-iosxr");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur62957");

  script_name(english:"Cisco IOS XR Typhoon-based Line Cards and Network Processor (NP) Chip DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XR software
that is affected by an error due to the improper processing of IPv4
packets routed through the bridge-group virtual interface (BVI)
whenever Unicast Reverse Path Forwarding (uRPF), policy-based routing
(PBR), quality of service (QoS), or access control lists (ACLs) are
enabled. A remote, unauthenticated attacker can exploit this error to
cause the device to lock up, forcing it to eventually reload the
network processor chip and line card that are processing traffic.

Note that this issue only affects Cisco ASR 9000 series devices using
Typhoon-based line cards.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150415-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ebd0350");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38182");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCur62957");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCur62957.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# check model
model = get_kb_item("CISCO/model");
if (model)
{
  if (model !~ "ciscoASR9[0-9]{3}") audit(AUDIT_HOST_NOT, "ASR 9000 series");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_HOST_NOT, "ASR 9000 series");
}

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

# Rough version check
if (
  version !~ "^4\.3\.4($|[^0-9])"
  &&
  version !~ "^5\.1\.[13]($|[^0-9])"
  &&
  version !~ "^5\.2\.2($|[^0-9])"
  &&
  version !~ "^5\.3\.0($|[^0-9])"
) audit(AUDIT_HOST_NOT, "affected");

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

override     = FALSE;
is_typhoon   = FALSE;
bvi_enabled  = FALSE;
urpf_enabled = FALSE;
acls_enabled = FALSE;
qos_enabled  = FALSE;
pbr_enabled  = FALSE;

missing_pie  = '';

# Cisco SMUs per version (where available)
pies = make_array(
  '4.3.4', 'asr9k-px-4.3.4.CSCur62957',
  '5.1.2', 'asr9k-px-5.1.2.CSCur62957',
  '5.1.3', 'asr9k-px-5.1.3.CSCur62957',
  '5.2.2', 'asr9k-px-5.2.2.CSCur62957',
  '5.3.0', 'asr9k-px-5.3.0.CSCur62957'
);

if (get_kb_item("Host/local_checks_enabled"))
{
  # First check for Typhoon card(s)
  # If no Typhoon card, then not-affected.
  buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
  if (check_cisco_result(buf))
  {
    if (
      "A9K-MOD80-SE"   >< buf ||
      "A9K-MOD80-TR"   >< buf ||
      "A9K-MOD160-SE"  >< buf ||
      "A9K-MOD160-TR"  >< buf ||
      "A9K-24X10GE-SE" >< buf ||
      "A9K-24X10GE-TR" >< buf ||
      "A9K-36X10GE-SE" >< buf ||
      "A9K-36X10GE-TR" >< buf ||
      "A9K-2X100GE-SE" >< buf ||
      "A9K-2X100GE-TR" >< buf ||
      "A9K-1X100GE-SE" >< buf ||
      "A9K-1X100GE-TR" >< buf
    ) is_typhoon = TRUE;
    else audit(AUDIT_HOST_NOT, "affected because it does not contain a Typhoon-based card");
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  # Check for patches next; only specific versions
  if (!isnull(pies[version]))
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_install_package_all", "show install package all");
    if (check_cisco_result(buf))
    {
      if (pies[version] >!< buf)
        missing_pie = pies[version];
      else audit(AUDIT_HOST_NOT, "affected because patch "+pies[version]+" is installed");
    }
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ("interface bvi " >< buf) bvi_enabled = TRUE;
    else audit(AUDIT_HOST_NOT, "affected because bridge-group virtual interface (BVI) is not enabled");

    # Next check uRPF
    if ("ipv4 verify unicast source reachable-via rx" >< buf) urpf_enabled = TRUE;

    # Next check acls
    if ("ipv4 access-group " >< buf) acls_enabled = TRUE;

    # Next check QoS
    if (
      "service-policy input " >< buf ||
      "service-policy output " >< buf
    ) qos_enabled = TRUE;

    # Next check PBR
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_policy-map_include_pbr", "show running-config policy-map | include pbr");
    if (check_cisco_result(buf))
    {
      if ("policy-map type pbr " >< buf) pbr_enabled = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (
    is_typhoon
    &&
    !override
    &&
    (
      !bvi_enabled
      ||
      (bvi_enabled && !(urpf_enabled || acls_enabled || qos_enabled || pbr_enabled))
    )
  ) audit(AUDIT_HOST_NOT, "affected");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCur62957' +
    '\n  Installed release : ' + version;

  if(missing_pie != '')
    report += '\n  Missing update    : ' + missing_pie + '.pie';

  report += '\n';
  security_hole(port:port, extra:report+cisco_caveat(override));
}
else security_hole(port:port, extra:cisco_caveat(override));
