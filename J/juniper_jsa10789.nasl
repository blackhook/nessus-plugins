#TRUSTED afcde168e46d8f04333ef780b29e6cab5af649d4b36254762050ad5d705d48cbab78d3bb7e072c246acfb2547ba0ea7250ba2a12ef80a34026b59f76c26e858e9b63f93df8b52da4b045674e1f3ed1f24bf70d31f4ddab1be22d0e5b707e063d81ef65ba61509701ae7f832f0401e7e5b880b39e79e7ad6dcb47db8b53e88f1e6b6c637c634057fb5104bd33f701749068e536bdf800eb1ff4602b53a6c95534339bb44438c2ec39f5f126fd55b13ab93b882c9ed1e22a54777a77915c38859c87cae6510d29b94a1278f366c9b50764a1e251ebb21a2dcf73985956ebb0bdcadae458fa6860f4ce0c674c70935669565607598ebaad081db0954265b1071978d8f8e1d3f0fc754ce54c6dfd44ab3e4ade3b59444e4a8f9d510e8b918820fe0fb6bcd5996ddd11b951b88826638add1d3f3504fd54ef8315a1ffea9ec16a1c21464765202bb923af34b6f5a5277bda3adba9c1df287ecd261e3164f03f1e34917e95c77f8263bd500dd786777594ee37292b64cf1048b3022971175ac7eff5087f6d6928978fcd45728f1397b8b6cac1a531f3b2525ee35f31ebcb57c8ce796beb5c621cf6e9b0057c9ba63e0ac5729e871e7d62c3c141a30b92527727f59046f67f9fde41cbc5709812e9983f29daa724a9324f9bd41605a2b1e3ac5da280254626548a6d971c98a2a963791027d6dd1f6a64170ce7730b2fcba78c2c064a93
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102702);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-10605");
  script_xref(name:"JSA", value:"JSA10789");

  script_name(english:"Juniper Junos SRX DHCP flowd DHCP Packet Handling DoS (JSA10789)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in flowd due to improper handling of DHCP packets. An
unauthenticated, remote attacker can exploit this, via a specially
crafted DHCP packet, to crash the flowd service.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10789");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10789.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(
  model:model,
  flags:SRX_SERIES,
  exit_on_fail:TRUE
);

fixes = make_array();

fixes['12.1X46'] = '12.1X46-D67';
fixes['12.3X48'] = '12.3X48-D50';
fixes['15.1X49'] = '15.1X49-D91'; # or D100

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If DHCP isn't enabled in some form, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  pattern = "^set system services dhcp";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have DHCP enabled.');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
