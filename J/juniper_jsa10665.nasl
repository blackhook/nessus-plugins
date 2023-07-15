#TRUSTED 38b4a369d1412cf070926bf81292dc583a4ca8e0dda68a8441598f94ab7fe51e3085e3a8cdd882102b6846064057324eed9c2bbe9f6512ec8eeee9086dd392b6e254ef54cb4ff3c638c9de0b135efabf8bd192eab91ac534bc82b9c50941c8509ffd1fb3127e350425c7d9370e01c2448bebfe3300ae1fda474be47a03faa8189ba8b3944e0f8acc0f9a03ae58a4ea8a07c3fba8d6937df93f753f7490d64b6fbee1896b13ba9b1e09737368ba7df306de1f72379bfd4234ba8265bdf73deaf9ceeebf26f0cb760a9cc5efe6bc080ef4a0ddbb13ca0ddbb0c2f7f03822a96d68ec343f99c5e4132edda98e9679c5fd0a8376c5a7b3aebf087e4fd91a1935c81226d8754172ae38d2e37990cacc33e70a657f612506d28b4e6ca60b0ef8a4a257c29f074563e0f78802b32bdbba09f8fbc6fce4d7ae58c266bed0b09a0bf69c707471262935a02be8773907c64782ec8013df3f9bd804e4807214462bed4936c8be16f4a3f8611d29fa80b924c25d0f08a2a50b79dd3889c117981134e2e8bdfd11c8a7d7b2f7e58f859663c5aa2b9a2e2a74967b02314013e41d395521f82be134ce7ada14fd904adffbbd5fa293ba2d05cd61031c702eddc07d04504c8d0b4def2e660cdefc2a7e6e997ef63db1a286756d3aa907af80995f0126ffaf7a9af07fe1b8c710339704cb6bb1e8a977212aba04387747553f5355480e663700f2ff
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80953);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-6382");
  script_bugtraq_id(72070);
  script_xref(name:"JSA", value:"JSA10665");

  script_name(english:"Juniper Junos MX Series BBE Routers jpppd Remote DoS (JSA10665)");
  script_summary(english:"Checks Junos the version and model.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability in the
Juniper PPP daemon (jpppd). A remote attacker can exploit this issue
by sending a specially crafted PAP Authenticate-Request after
successful negotiation of the PPPoE Discovery and LCP phase, resulting
in the PPP daemon crashing.

Note that this issue only affects MX series routers deployed as a
broadband edge (BBE) router.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10665");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10665.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:MX_SERIES, exit_on_fail:TRUE);

# Only versions 13.3R3 and later are affected
if (ver =~ "^13\.3R[0-2]($|[^0-9])")
  audit(AUDIT_INST_VER_NOT_VULN, "Junos", ver);

fixes = make_array();
fixes['13.3']    = '13.3R6';
fixes['14.1']    = '14.1R4';
fixes['14.1X50'] = '14.1X50-D70';
fixes['14.2']    = '14.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for PAP authentication 
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set interfaces \S+ unit \S+ ppp-options pap ";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because PAP authentication is not enabled');

  # Check for the Broadband Edge (BBE) subscriber management daemon
  buf = junos_command_kb_item(cmd:"show system processes");
  if (buf)
  {
    if (!preg(string:buf, pattern:"bbe-smgd", multiline:TRUE))
      audit(AUDIT_HOST_NOT,'affected because the Broadband Edge (BBE) subscriber management daemon is not enabled');
    override = FALSE;
  }
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
