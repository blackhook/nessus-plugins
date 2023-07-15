#TRUSTED 43b221f1b62401b7db20d568c4dbf568fa6f22357384cca638842210c5d3b4ae75e14827c1358e3cff5fcf548291b9a12d680d1a50b7121b27f6dbb873d399859fc17549cbd7c491bffb8860af713e1ac4cdba80d30a3208287c2d3f151900dc929069879316ecc8a25f2ff66ceb3cb75d603105fe30e7835e02e63a66c94b0ee500e3c79dcb96f28a0bf13e80e753948e2973fc4d71ee88658737d35dd129758cd06fa1779dd7ac810ce17579048143ebb2928f5e035c7eca6851c886bb7866de412a1159c4b85d4e205e5069a10b420c7650fa80312d3f21b782cfacbf603e6ae25605140707ce67b203fe0819487d76424d42439cf4000a83948310b82f57fee9c2edafc2de2facd57af8eb30e4a5d408c1b6d48bf4dc43230de72384cce98517d83f9e83c3d6e2c3887951c9fa663c2934ae6f3c494c59d3e7870f4cf05b88c4670bd059cb481f6a23eb9937daa37bf9bbbc24a3f9fa8aecefd4abeb9d4cc15178243c9a19220c0c0f0f618c9dd38cda0537e4765b1658ff071ed15ed6f3b27710555ecfed2f2a6be648cc5be0b971e47974b23385f21f83c5bbb14eef6c4dc7a74940c0f70c5df06e1cc54a050a047daed7aa4c5e9f8ec4d2abacda65abb1113ac9d52280ed1ae945f335318896f57157cb1c86d35400f5bc5e55b471326d9470f9dd9bdd47ab0446ce2a982954e023d7218cbb9abca57e662f761ad94e
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156782);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/27");

  script_cve_id("CVE-2022-22179");
  script_xref(name:"JSA", value:"JSA11285");
  script_xref(name:"IAVA", value:"2022-A-0022");

  script_name(english:"Juniper Junos OS DoS (JSA11285)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability in the Juniper
DHCP daemon (jdhcpd). An unauthenticated, adjacent attacker can exploit this, by sending a DHCPv4 packet with specific
options to the host, to cause jdhcpd to crash and restart.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11285");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11285");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22179");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.4R1', 'fixed_ver':'18.4R3-S10'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S7'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S4'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S4'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S6'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S2'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S1'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2-S2', 'fixed_display':'21.1R2-S2, 21.1R3'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R1-S2', 'fixed_display':'21.2R1-S2, 21.2R2, 21.2R3'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R1-S1', 'fixed_display':'21.3R1-S1, 21.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set system services dhcp-local-server group.*interface") &&
      !junos_check_config(buf:buf, pattern:"^set forwarding-options dhcp-relay group.*interface"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
