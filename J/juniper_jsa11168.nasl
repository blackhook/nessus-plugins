#TRUSTED ace47161a14af948549cd569a2ec455441f5fc5e4c1e2cb0b413bf84059fb6b882d65c812d1b22f15b0add6d58a092b31a3f84f630c82dce2cb13a6a45281e25393d803dee27fff34dea964dc6f3cd11a0e0dd7cbe6144eef4e0a906b81fc643ac7cc5d7c0baf85c09898880fb69c63259473d0f7c566534b7911905a3f0b08b5632a80e12cc429e9f20c7570a70447f072429416f1818714d3a2de222ad1fbbf006fcc3bcb6191e67b89295f2c31ad20b6c432543aa10ccbe36f3b753970846006955cf4e83f709bfa58698baad08aebbf04426d92554a8dc8c32b2abf9011e7b742dbdbc7b9250201def3c7738906e9441dffeadf8140f216107a4118e757efd432ce65407faf52189035a7aca1dfbdb53cbaff0f3f879a60b4448769f1e5fe748aae3976d1e76e6e0b6268ee5f6c0d4246fa6ccd78a9478e601d58e986897505fe6bb874ecd3f6701024b6ae274b0d9c5f887cfc0ceefae24d2a2bae5695823703eaba302b64199a4e776dbfed04d3ac52e0e95773a17cea46a77372a8f37e7c4bb07c3f4d8b9591b62f1fb1e73b43d2fcacb3a3a91e4195ba7b985003702806a0df7302e75c67454f044ee465ee1b3bf8a190c786dc6591908a265a08515e28a6a6e29365679ff1f4c2c21a1cbd096c0cac4920859797d4a99294b287c1da64970f14f87312e9960969acce39ff19458e2d8067bef28c8f45240656ec9f9
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149351);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/27");

  script_cve_id("CVE-2021-0240", "CVE-2021-0241");
  script_xref(name:"JSA", value:"JSA11168");
  script_xref(name:"IAVA", value:"2021-A-0215-S");

  script_name(english:"Juniper Junos OS DoS (JSA11168)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by denial of service vulnerabilities as referenced
in the JSA11168 advisory:

  - On Juniper Networks Junos OS platforms configured as DHCPv6 local server or DHCPv6 Relay Agent, Juniper Networks
    Dynamic Host Configuration Protocol Daemon (JDHCPD) process might crash with a core dump if a specific DHCPv6
    packet is received, resulting in a restart of the daemon. The daemon automatically restarts without intervention,
    but continued receipt and processing of these specific packets will repeatedly crash the JDHCPD process and sustain
    the Denial of Service (DoS) condition. (CVE-2021-0241)

  - On Juniper Networks Junos OS platforms configured as DHCPv6 local server or DHCPv6 Relay Agent, the Juniper 
    Networks Dynamic Host Configuration Protocol Daemon (JDHCPD) process might crash if a malformed DHCPv6 packet is
    received, resulting in a restart of the daemon. The daemon automatically restarts without intervention, but 
    continued receipt and processing of this packet will create a sustained Denial of Service (DoS) condition.
    (CVE-2021-0240)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11168");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11168");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0241");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S12'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R3-S5'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S13'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R3-S8'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R3-S5'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S8'},
  {'min_ver':'18.4R2', 'fixed_ver':'18.4R3-S7'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S5'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S2'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S2'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R2-S3', 'fixed_display':'20.2R2-S3, 20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

# set forwarding-options dhcp-relay dhcp6
# set system services dhcp-local-server dhcpv6
var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  var pattern = "^set forwarding-options dhcp-relay dhcpv6";
  var pattern_local = "^set system services dhcp-local-server dhcpv6";
  if (!junos_check_config(buf:buf, pattern:pattern) &&
      !junos_check_config(buf:buf, pattern:pattern_local))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos', ver);


}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);