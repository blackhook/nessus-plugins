#TRUSTED 9408919e6cadeff01134ffff6dd618a87dc7286bb7c43a24ce4530de9bb2c2017989bb0a03a6413a0ea1c36f89274e5c9c84b921775dc3dd76f5f4e5a3af80b769644bc96f72182877a9fbb8df2e302ca5137457805ea13778c837d1709709ee280a0f0a7d25d6239e103cc608bec4d46fcc167c3f2ab5f6a0973d6c7530d6841fe1f999c3d12943aba8536da1d1bf53e7806eed78fb6e17d19cdca1074ace12ea583b13acb3ce01ef8599a9ce0348d784a52f5778877c7aad741696fd6fc60d741967c828709bf84ca7fad8bacff466cca9541de9c4e59cf1517c0d00bcde0589c93cbf7f4806e64f415057c0fd293285ee54fcfa56e32924aa70b1cb25472cfd5070417551ed4f04b0100e5509bb73de4adff973a3c8c282ecb7fad396da907351a89869ef3ef857c66ac352995394104ab5139cdcde53e611d9576716b75505e033a6f286d1b700cb0808ecadc8c930f170be0e3151196f6c093c2b733002ef1b49732a879c6b5ec488354a574269575396e55899a62ca9a26ea5aec6f0b4dba914864e1ab273a08ee50359d7e5490eab22b199c6c9fe1bbb739c91eee32daee9d932785aefbef07c0cf64f9d4d8e7eb140875fa12d69c707734473a8d763eafd13b9a299f9a1a79f926d10ef6749bd7adb210d8a12f7a92fd3190deb13cc887288f6ee41c10fc8f2e693dcd2ef17b6e4404d9375b0057f6e1d1d6e99137c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99527);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2340");
  script_bugtraq_id(97607);
  script_xref(name:"JSA", value:"JSA10786");

  script_name(english:"Juniper Junos for M/MX Series Routers IPv6 Neighbor Discovery DoS (JSA10786)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the remote
Juniper Junos M/MX Series device is affected by a denial of service
vulnerability in a Packet Forwarding Engine (PFE) when processing IPv6
neighbor discovery (ND) packets that originate from subscribers and
are destined to M/MX series routers that are configured with Enhanced
Subscriber Management for DHCPv6 subscribers. An unauthenticated,
adjacent attacker can exploit this to cause the PFE to hang or crash.
Note that this issue only affects devices whose system configuration
contains 'subscriber-management enable force'. Furthermore, devices
with only IPv4 configured are not affected.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and current configuration.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10786&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c1c5682");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10786.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^MX?")
  audit(AUDIT_HOST_NOT, 'an M or MX device');

# Workaround is available
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array();

fixes['15.1'] = '15.1R5';
fixes['16.1'] = '16.1R3';
fixes['16.2'] = '16.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration");
if (buf)
{
  if (preg(string:buf, pattern:"subscriber-management enable force", icase:TRUE, multiline:TRUE))
    override = FALSE;
  else
    audit(AUDIT_HOST_NOT, "affected because DHCPv6 subscribers is not enabled");
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);
