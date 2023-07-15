#TRUSTED 1cdd53624f3b544ad013a470e5047c01424ffa57ec8c016faa4a411d0f64a6d82dfe40f308f487f8a4d006bacef541f6a27fedce86035dae150073f94b1cbab07fd722c1bd2389891142143154a6fc2e2f3b48f03eee0d9f0470b95f07ba9dfa4ab5ae9a1a0bac4f7eaf4a53e443f32518f78ad13d35c9c6e1e4bf6479c6d2d435e3c2d13c571a17418547637d5a98de4577cefefb2f8931ca3cb56ba2f3e1b42589d4296dfc453e7c98ea0fe524af13890d8df5471f9db3531912fd3d5451b5460060c69852b2330f0e0bd54dcceab98f955e2e4a4aff90707ad98f50d23682dfefa6636f2c0f97ab567664190e34e5a1e3662a3444d8841085c6ba856aad7dde57546713319c2519726710cb5d5e453fe63250cc5f48f8a4daa26d5ac260fad22a8b8d0b4dda4f7f90ec02e67ae879c3d03d67306f31f6a8586f18de590c4ce62fba7ef0e8601282fd49370a0add50508f112340852db8991e54434791ea6ea5f150f99ed8fd21fc2349b97eaafd87557dd735e43a169977bf227f4d966086a0a6a3bedd48203f62be7c23677f1daa29dc423cfb9dcc10463b7bf80b5ea165d021f50be0337cf528aa068d1af564293c45b7d3bebc6c386ce2cc04e0d430cc6f4b3657def4c26a0ee4e863b9f414b46a36ade3b20f7f15c4fdbde7958c703ceb9b1e95c702addaf936b39088edc0bcdba57230a8556726d20de398999ee53a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76504);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-3817");
  script_bugtraq_id(68545);
  script_xref(name:"JSA", value:"JSA10635");

  script_name(english:"Juniper Junos SRX Series NAT IPv6 to IPv4 Remote DoS (JSA10635)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a denial of service
vulnerability. A remote attacker, by sending a specially crafted
packet to an SRX series device, can crash the 'flowd' process when the
packet is translated from IPv6 to IPv4.

Note that this issue only affects devices with NAT protocol
translation from IPv6 to IPv4 enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10635");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10635.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

# if (compare_build_dates(build_date, '2014-07-31') >= 0)
#  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

if (ver == '12.1X44-D32') audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['11.4']    = '11.4R12';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if NAT protocol translation from IPv6 to IPv4 is enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set services nat .* translation-type basic-nat-pt";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT,
      'affected because NAT protocol translation from IPv6 to IPv4 is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
