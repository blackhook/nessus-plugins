#TRUSTED 1086225206704c5a50e0219a9a09d3e458886fd7ccd5cd07c6d4a2bfac9612c36e33f2e480bfa354fc1dc6523e152f738bf748454ffe21a5e80976404fbdd6152cf1b5e6d8ad9c85cf0d5389fa5b4d77b0cba6e6f92bcd58ef0a023fa1a7312771eb99499ad1eef7501a5583672ebb5f967c5dd0f27287e0321e550dc000c862003131d29bf0b3bd96b1c9b75610d8cfb72b5b87222edb64694bdc3ff810ddd4db6cfc27d26fb2c6247523179aef205ad86479833b6b43f42543d9c025e957d1a5eb4f1a5d280f457e6034f885e864b38c31d2c5a0a42915695da58d42d6d026fd14a543e42039ee873be3b47b1fa682f3d67f80a727840ec1af60529bcf5e8485fc254353001efbe8e5d322f9d983ba1bae81ec38192e4d0dd89c088cb6227451248e4fab35b62dcd1b20e9e368481de228087f50d9b649357a04b73aeec390a6f58154c25ee2cef868fe68427a0787a42340a0937f711d9d5a047d5d7d1f0495dc3f0bb0a418557cd079a68e5f09e3f0b8d64ec679c99956e73358c5cbb35a2dc2af5a42326e60cee0ea999bd3675316023af55988cc51cab1e653805d4dd419f20e144094f5c7ba1238913462b315464945606eb22ef7edbf26d83f84cd5d123ac20b1cb51f8223e9def6098d3ce4f53b34e1020f4bd83ef1435eb1098fe159ec67bf8b44a85b4ba68f571f72acff602133773d1590300a8c3dc6561230ed
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86606);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2015-7748");
  script_xref(name:"JSA", value:"JSA10701");

  script_name(english:"Juniper Junos MX and T4000 Series Trinity uBFD Packet DoS (JSA10701)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is potentially affected by a denial of service
vulnerability due to improper handling of uBFD packets that are
received directly by chassis that have the 'Trio Chipset' (Trinity)
MPC. A remote attacker can exploit this issue, via maliciously crafted
uBFD packets, to crash the MPC line card.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10701");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10701.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "(^MX[0-9]|^MX-MPC[1-4]|^EX9200|^CHAS-MX|^MPC[4-]|^T4000-)")
  audit(AUDIT_HOST_NOT, 'an MX Series, EX 9200 or T4000 router that supports Trio (Trinity) chipset line cards');

fixes = make_array();
fixes['13.3'   ] = '13.3R8';
fixes['14.1X50'] = '14.1X50-D110'; # PR1102581
fixes['14.1'   ] = '14.1R6';
fixes['14.2'   ] = '14.2R5';
fixes['15.1R'  ] = '15.1R2';
fixes['15.1F'  ] = '15.1F3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Label-Switched Interfaces (LSI) / Virtual Tunnel (VT) interfaces w/ MPLS IPv6
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols mpls ipv6-tunneling";
  if (junos_check_config(buf:buf, pattern:pattern))
  {
    pattern =
      "^set (logical-systems|routing-instances) .* (no-)?tunnel-services";
    foreach pattern (patterns)
      if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;
  }

  if (override) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

  buf = junos_command_kb_item(cmd:"show chassis hardware");
  if (buf)
  {
    # Trio-based PFE modules part numbers
    #  https://kb.juniper.net/InfoCenter/index?page=content&id=KB25385
    part_numbers = make_list(
      "750-028381",
      "750-031087",
      "750-028395",
      "750-031092",
      "750-038489",
      "750-038490",
      "750-031089",
      "750-028393",
      "750-028391",
      "750-031088",
      "750-028394",
      "750-031090",
      "750-024884",
      "750-038491",
      "750-038493",
      "750-038492",
      "750-028467",
      "711-031594",
      "711-031603",
      "711-038215",
      "711-038213",
      "711-038211",
      "711-038634"
    );

    foreach part_number (part_numbers)
    {
      if (part_number >< buf)
      {
        override = FALSE;
        break;
      }
    }
    if (override) audit(AUDIT_HOST_NOT, 'affected because no Trio-based PFE modules were detected');
  }
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
