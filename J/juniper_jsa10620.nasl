#TRUSTED 0c46d2ada7e0bb6936aeb0d3ac0ff57cc6a35ed0982302135363eba591991377873a69955054c457953c20a78b4ba93a19e54134818581411e88ae152af02388abe4cfabda1f2edffc12b076ceb23b22868b9100a941fe5a2c72a0c6f0584d09c7915f40a75d3dd35c3c4cbe56998b9a72a1f3aabf50da90b6f9a8afd215650880258724fdccfd3376f1af22e7152cdaf46f1bc7c899d4cb8758e48a48729e59d793bb537f5b57ac83e8ec2fd17ee615595dbb93ed0fcd61201560879dcb0003c0d6fa5b5ab33b2b3db1a9cf0df5271a15a79c1e55e390094bbae1eaad207bcd259dd513b641ff4d9c96c228873069f3248a9a19f421f5e2f2a49d503ce73d98666b8c5eac53b52673c87b218a872e3b9d46ec186abb33b8e97d7e07d33315658af115a289abdf251b2a4e170d4c94defcd06373cff94f3045073658b4bac6198dacaaf8bbe351e4f09ca18772907272b351eb5293263edfb7b36ee0a5f5d5666dc4cb8507010d1390b6aad41e53920054bef6d874b641673a7a2347cd24a27adc5385eac1ade2c8b6075a4558f8c29c5d3ac7730aafeec74c9479888c820c7fadbc8c6ad45be7aeed44dbede078ca4d345a6f107c100ccf2988c9c5c48f8699b19b484a7a27a00f55327a32e341d9cfc2ad74c282c20510bc3f8de06f2d757a282c85dbc993e47aedf34dda4403d20a1016bfad1ea7347967f2015ef6ae0d80
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73494);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-0612");
  script_bugtraq_id(66759);
  script_xref(name:"JSA", value:"JSA10620");

  script_name(english:"Juniper Junos SRX Series Dynamic IPsec VPN DoS (JSA10620)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability related
to the Dynamic IPsec VPN service. A remote, unauthenticated attacker
can exploit this vulnerability to cause new Dynamic VPN connections to
fail for other users or cause high CPU consumption.

Note that this issue only affects SRX series devices with Dynamic
IPsec VPN enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10620");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10620.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");

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
include("junos.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (
  model != 'SRX100' &&
  model != 'SRX110' &&
  model != 'SRX210' &&
  model != 'SRX220' &&
  model != 'SRX240' &&
  model != 'SRX550' &&
  model != 'SRX650'
) audit(AUDIT_HOST_NOT, 'a SRX Series for a branch device');

if (compare_build_dates(build_date, '2014-02-19') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '11.4R10-S1' || ver == '12.1X44-D26')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['12.1X44'] = '12.1X44-D30';
fixes['12.1X45'] = '12.1X45-D20';
fixes['12.1X46'] = '12.1X46-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Dynamic IPsec VPN must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Grab the dynamic VPNs
  lines = split(buf, sep:'\n', keep:FALSE);
  pattern = "^\s*set security \S+ gateway \S+ dynamic ";
  gateways = make_list();

  foreach line (lines)
  {
    matches = pregmatch(string:line, pattern:pattern);
    if (!isnull(matches[1]))
      gateways = make_list(gateways, matches[1]);
  }

  if (empty(gateways)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
  
  # Check if IPsec is enabled for at least one dynamic VPN
  foreach gateway (list_uniq(gateways))
  {
    pattern = "^\s*set security ipsec vpn \S+ \S+ \S+ " + gateway;
    if (preg(string:buf, pattern:pattern, multiline:TRUE))
      override = FALSE;
  }
  if (override) audit(AUDIT_HOST_NOT, 'affected because Dynamic IPsec VPN is not enabled');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
