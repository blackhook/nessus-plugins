#TRUSTED 75b3776e363f33aa5a73f67c395efb98e010b6f57939c217bcd2be17960c0e59177c9b76a1d8b33846ded098ac280397bb001696ce115cf1b5ed4d383d542ee77602f881c351c6c91073807c984491388fcbc92f51f2670f4c208d2846f70b80ac266533234723be024b433c8488c6c85784a5230bc08db12acbc7b8c315ae03f2b67e656914a1d7136df75eae2f4fa16c222b7b48190eadb7bdab6c3791d9f8882b3529832eec1dde4728f037689ebf815c8a9cb51ac76f612c0ab723b2d1b84caf7741ffe282642afb6166a4c856b54986461241241c1725dea6286c0edc39f3d266d016289c16ab932dd3ba7b98a730068b389af2f23f64df7ca27eb9c74bd6f206bb1b1042beda18d9b886cbf965682d10ecdfefa334432605eb808e7856665ad586fb5305382588e0490a5df41c9743458d3c447857433e9749c792daa51ceb9e5dca7c8fc652a329bf07edede77c13c66eea879c297cfaa6daeeaf7ec377be4fc7b641c3180da2270c6d424737c084ac96a4fc446fd400d8e42bdca88916eac59bf41a8a53228705cfe4ad33cbd0ce77429addb354554b4eef01922e863e86438ccf1134470cd586856538193a314b2f7831eeb285f18fccc628b2a171f04ba451997acfc3c5cd06184eb1959b4fba0a025604bfbb0280760f19184ebdaeca8c12554dd5f6805963c0e7bc8f76f3ef8ecd9a6ea1d8fdf2a3affbdfac55
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78421);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-3825");
  script_bugtraq_id(70366);
  script_xref(name:"JSA", value:"JSA10650");

  script_name(english:"Juniper Junos SRX Series ALG 'flowd' Remote DoS (JSA10650)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a denial of service
vulnerability related to ALG (Application Layer Gateway). A remote
attacker can exploit this issue by sending a specially crafted SIP
packet to an SRX series device, resulting in a crash of the 'flowd'
process. Repeated exploitation may result in the device becoming
unresponsive.

Note that this issue only affects devices with any ALGs enabled or if
flow-based processing for IPv6 traffic is enabled. All SRX devices,
except for SRX-HE devices, have the SIP ALG enabled by default.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10650");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10650.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

fixes = make_array();
fixes['11.4']    = '11.4R12-S4';
fixes['12.1X44'] = '12.1X44-D40';
fixes['12.1X45'] = '12.1X45-D30';
fixes['12.1X46'] = '12.1X46-D25';
fixes['12.1X47'] = '12.1X47-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
override = TRUE;

# Check if either configurations are enabled 
if (get_kb_item("Host/local_checks_enabled"))
{
  #  Check if flow-based processing for IPv6 traffic is enabled
  vuln     = FALSE;
  buf = junos_command_kb_item(cmd:"show configuration | display set");
  if (buf)
  {
    pattern = "^set security forwarding-options family inet6 mode flow-based";
    if (junos_check_config(buf:buf, pattern:pattern))
      vuln = TRUE;
    override = FALSE;
  }

  #  Check if at least one ALG is enabled
  if (!vuln)
  {
    buf = junos_command_kb_item(cmd:"show security alg status");
    if (buf)
    {
      pattern = ":\s*Enabled$";
      if (preg(string:buf, pattern:pattern, multiline:TRUE))
        vuln = TRUE;
      override = FALSE;
    }
  }

  if (!vuln && !override)
    audit(AUDIT_HOST_NOT,
      'affected because neither flow-based processing for IPv6 traffic is enabled nor at least one ALG is enabled'); 
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
