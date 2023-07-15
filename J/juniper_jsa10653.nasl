#TRUSTED 023cbf17684f4556a8554fcd9613fecf7ded4cff7cf7b7209e626d8bbb60e40fb2a93f55a1dc220b98310746b78d8afa4e8a6561048aad96598ae9303eaa9d8b28b47972d004ec06976646af4ba1b9089f6f78283428de65c184de1a5c5967548049d257ebae978cc794d9f08fdb378afa529654980accee9ea65ac7c2b26768e181d008549227e6691721302951a5125aa21f6b2fb872725e9d65ab1dd36bd081e83bb7591fbff0d6e1e38801badf0ace3b3d858d29420f798d7b5e630242cb97155a962213c398439e77ba2688f679ebe1f7e8eb715aad711409aa3cffbc4734e1eae48b684bf4342bcab166a04b764abf4e46c4040aeb4ef7604267691b1ee156c179220be1c94dced7bb95dd5ed9169b92154343bdd60ccd98d48df53f97d1b4d718641b06a54f9626768606ccb427d63a79d0c1fe607e37eac67965c930b2fe171f9526867d137bef518f972f26123c5150d2de931d786a17f2b6ddd33cdf179741719ea950825d0d6c7b2e487a9b8b5ef2558f2a40c334787e184413ec33e7fa9f27f80eb6e00feeb3dc42ce7dbb4717827276e96455eb38a60e685c0f82ea478755a6e0be9a0d3a03774e0d28b34eac029c7ccfc558ee37e6118eec39d015d71b9195e64af4575f5c42f0565879ad862c1bf574bcd550242da9cc14bee5c8f47fcd9210f3596466cc5e8f65bef7d5e5c41e65d6c5c4b5c512a3c21019
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78424);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-3818");
  script_bugtraq_id(70361);
  script_xref(name:"JSA", value:"JSA10653");

  script_name(english:"Juniper Junos BGP UPDATE 'rpd' Remote DoS (JSA10653)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
improper handling of BGP UPDATE messages using 4-byte AS numbers. A
remote attacker can exploit this issue, by sending a specially crafted
BGP UPDATE packet, to crash the 'rpd' process.

Note that this issue only affects devices with the BGP daemon enabled
and support for 4-byte AS numbers.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10653");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10653.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['12.1']    = '12.1R10';
fixes['12.1X44'] = '12.1X44-D40';
fixes['12.1X46'] = '12.1X46-D30';
fixes['12.1X47'] = '12.1X47-D11';
fixes['12.1X48'] = '12.1X48-D41';
fixes['12.2']    = '12.2R8';
fixes['12.2X50'] = '12.2X50-D70';
fixes['12.3']    = '12.3R6';
fixes['13.1']    = '13.1R4-S2';
fixes['13.1X49'] = '13.1X49-D49';
fixes['13.1X50'] = '13.1X50-D30';
fixes['13.2']    = '13.2R4';
fixes['13.2X50'] = '13.2X50-D20';
fixes['13.2X51'] = '13.2X51-D25';
fixes['13.2X52'] = '13.2X52-D15';
fixes['13.3']    = '13.3R2';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == '12.1X47-D11')
  fix = '12.1X47-D11 or 12.1X47-D15';
else if (fix == '12.1X48-D41')
  fix = '12.1X48-D41 or 12.1X48-D62';

# BGP must be enabled and the router must support 4-byte AS numbers
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set routing-options autonomous-system 1.10";
  if (junos_check_config(buf:buf, pattern:pattern))
  {
    # Check if BGP is enabled
    buf = junos_command_kb_item(cmd:"show bgp summary");
    if (buf && "BGP is not running" >!< buf) override = FALSE;
  }
  if (override) audit(AUDIT_HOST_NOT,
    'affected because BGP is enabled and configured to 4-byte AS numbers');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
