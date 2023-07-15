#TRUSTED 0fb0ae16c5f48972089cda867021b5315f892d5006e531a8f641562602dafb68228a3e238ffa4da562ef0d453543c92110b314e6c4c3ecc34d816952d13fc8ec7ae2115c32d801cd4e3b740469f6c2e372640becd7437979208aee7772683fce51dc5f44e37b0bad673a9a2bda5222c2c1a4f98a7614b96c9f53b1b365d797343219d8d9762cdee3f5b23a169ad4a2a9318c5975cfc7d72f81e5a0009c6e5b8572d6adb9c063453f6e6cefa058cc992503b7cfd5aa19bb53d024a146f4f990866d6e4b8c9c084a56080aeb16cede72c75369fe4b3cb5f33cc0a31f74047a3aa7c3aa346911a52b783b0aa7f07c16c3b434b2ffb3c05c015ac572662440668e4afbcbd4b28ab4cb448b27c532a1972aa5044465c564f0dda529c5e14395a97510c4d2dd97b55996067030d4d94a2fa140846934a21bc5b9de01d2309d58f01447e5a983cf89aa1b221bdc5fad255ed4d852094805a2e189e6108cabd241865e58fd18924aead43277e70f4b894955009c0566dcdf68f8b91d13915c10e4c3a7b19ec28f59954d01afc295b5f29609d2c3069e34b8eb3509b874ec3dc91578809ecb1072fb8219c91bbcbade508f52fd3f67787cef825b7ad9082b6a3bb1ec60939633ffe5e802981cbb5c16e952d489135c31a10a6ef2f12ff897d09cb2135f8dbcde5a0ad3391a6a7cec084b812f170eee4b35552964d2ba36b39ad760869fa1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77729);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2014-3335");
  script_bugtraq_id(69383);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup77750");

  script_name(english:"Cisco IOS XR NetFlow and Network Processor (NP) Chip DoS (Typhoon-based Line Cards)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XR software
that is potentially affected by a denial of service vulnerability
related the handling of a maliciously crafted packet with a multicast
destination MAC address routed by a bridge-group virtual interface.

Note that this issue only affects Cisco ASR 9000 series devices using
Typhoon-based line cards with a Bridge Virtual Interface (BVI)
configured for egress NetFlow collection with a static ARP mapping a
unicast IP address to a multicast MAC address.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35416");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=35416
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24842ba4");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup77750");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco bug ID CSCup77750.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3335");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2014-2021 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version",  "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Check version
# 4.3.0/1/2 are affected
version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if (version !~ "^4\.3\.[012]($|[^0-9])") audit(AUDIT_HOST_NOT, "affected");

# Check model
model = get_kb_item("CISCO/model");
if(!isnull(model) && model !~ "ciscoASR9[0-9]{3}") audit(AUDIT_HOST_NOT, "ASR 9000 series");
# First source failed, try another source
if (isnull(model))
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_HOST_NOT, "ASR 9000 series");
}

# Specific conditions are required
if (report_paranoia < 2) audit(AUDIT_PARANOID);

override = FALSE;

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # Check if CSCum91344 SMU is installed
  buf = cisco_command_kb_item("Host/Cisco/Config/show_install_active", "show install active");
  if (check_cisco_result(buf))
  {
    if (buf !~ "CSCum91344") audit(AUDIT_HOST_NOT, "affected because CSCum91344 SMU is not installed.");

    # Check if we have a Typhoon card, audit out if we don't
    buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
    if (check_cisco_result(buf))
    {
      if (buf =~ "\sA9K-(MOD80|MOD160|24X10GE|36X10GE|2X100GE|1X100GE)-(SE|TR)\s") flag = TRUE;
      else audit(AUDIT_HOST_NOT, "affected because it does not contain a Typhoon-based card.");
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCup77750' +
    '\n  Installed release : ' + version + 
    '\n';
  security_warning(port:port, extra:report+cisco_caveat(override));
}
else security_warning(port:port, extra:cisco_caveat(override));
