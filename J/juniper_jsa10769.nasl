#TRUSTED 863f24d68aa3603bf1499e29f9aeff5834c269e642fabc510888975c10d98c4ba68a935ed05189fdb16509a12c6957ed349faf8d1832e1c7e3fff842338d19f8b920e4b2660eb5effa85dd273d45042326afd8d5559ecfd53f2c9b51a10c73bc779d7688209e96e2bf7e53be02a768f152c7bffe584071bb2b0a3fee18b33ab25455aadfd89e42995d564337825626c7390cad2eb9a10ba81ef0ffc83ad8ae0a2ed8481fd5f285169e5815e48b4be2d3d08f472e13d28be0d3b59cb37df2acdf2f01a356765089689f53e4ab006c38dde8df2b96c50749324c34f20302bd6c4ecf9d7ebc8e7c8de340540670d1872ca1e64a0e21fb18e3d1e07f53bea22bbcd5f82fed065d11270e11208610638b2081a49c964b0eb7d888c1663c2ddee9e761c71f6c2d4a59f8f63e146e756d0e9882ef0ba993a6f91db2c62947c2dd596abec0ee7027c6565a38a1bf84c6e08a40f12b82d822940d39dff4ff0ba1030155cd83ea27021b165459769438da5012b380eccf5c7a98650406c3eb724342f3fa8d4b7b2422a235934fe9959eda880cf7c2018399a9cb25bf25ff340b2d72c15a0189d934b433afb431d32a871bac99a0fd9016b9da6883a664c6c2d6c1bff4f2e8e6b7442add0d1f23540761455118458a1f741c4dcb9c78ee1a63b0e55ab260ca5dea9b0b976b217c0680e3f60ebe4a2a0d374c18af33e21fb328019e09dff3ba
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96659);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2301");
  script_bugtraq_id(95396);
  script_xref(name:"JSA", value:"JSA10769");

  script_name(english:"Juniper Junos jdhcpd DHCPv6 DoS (JSA10769)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the DHCPv6 daemon (jdhpcd) when handling DHCPv6
packets. An unauthenticated, remote attacker can exploit this issue,
by sending specially crafted DHCPv6 packets, to cause a denial of
service condition for subscribers attempting to obtain IPv6 addresses.

Note that this vulnerability only occurs in devices configured for
DHCP services via IPv6 with either Server or Relay enabled. IPv4 is
not vulnerable to this issue.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version, model, and current configuration.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10769");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10769.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(
  model:model,
  flags:MX_SERIES | SRX_SERIES | EX_SERIES | QFX_SERIES | ACX_SERIES,
  exit_on_fail:TRUE
);

fixes = make_array();

fixes['11.4']    = '11.4R13-S3';
fixes['12.1X46'] = '12.1X46-D60';
fixes['12.3']    = '12.3R12-S2'; # or 12.3R13
fixes['12.3X48'] = '12.3X48-D40';
fixes['13.2X51'] = '13.2X51-D40';
fixes['13.3']    = '13.3R10';
fixes['14.1']    = '14.1R8';
fixes['14.1X53'] = '14.1X53-D12'; # or 14.1X53-D35
fixes['14.1X55'] = '14.1X55-D35';
fixes['14.2']    = '14.2R7';
fixes['15.1F']   = '15.1F6';
fixes['15.1R']   = '15.1R3';
fixes['15.1X49'] = '15.1X49-D60';
fixes['15.1X53'] = '15.1X53-D30';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if DHCPv6 is enabled as a server or relay
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Parse interfaces that have DHCPv6 configured
  patterns = make_list(
    "^set.* system services dhcp-local-server dhcpv6 .* interface ([^ .]+)(?:\.[0-9]+)?", # Server
    "^set.* forwarding-options dhcp-relay dhcpv6 .* interface ([^ .]+)(?:\.[0-9]+)?"      # Relay
  );
  interfaces = make_list();

  lines = split(buf, sep:'\n', keep:FALSE);
  foreach line (lines)
  {
    foreach pattern (patterns)
    { 
      matches = pregmatch(string:line, pattern:pattern);
      if (matches)
      {
        if (junos_check_config(buf:buf, pattern:matches[0]))
          interfaces = make_list(interfaces, matches[1]);
      }
    }
  }
  if (empty(interfaces))
    audit(AUDIT_HOST_NOT, 'affected because DHCPv6 is not enabled');
 
  # Check that the interface is enabled
  foreach interface (list_uniq(interfaces))
  {
    pattern = "^set interfaces " + interface + " .* inet6";
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    } 
  } 
  if (override)
    audit(AUDIT_HOST_NOT, 'affected because DHCPv6 is not enabled on any interface');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
