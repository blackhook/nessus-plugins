#TRUSTED 5123fe437409b06a90a5cf0159341d88b010ae6debc9d6a0e91d2ce5f903fd8f0ff4ef5b6a7176400479c79e6a1c7a32d6e5f7faba872dc0d4285a1b1ef35e372ef619aa25a797a9854ebabdc627a7ffb5b34c3f7ca3ce0982f6b268f4baf792aeb5a79cf1e1c7203e929a90500b494f3001ea4779db428f4f1e4e8eb3615e08691117b1a32c6cf51ff0b97871a958a20d1041c66e802043b1eb5b44658fb582bab78d5a4078cf1ccc7360d72a830a4eed2aec27841ca2ae8d3172cdcba96e57c079bef4b1d2a1530a7a1567572beb1ac49af3f6d9284b812e380385fd8875000f93e9216106dd34f2d57e2b75c870b84765c4c62e9be4cb8fc5f72850eb3311e1a3f68230e1be99b637ac8697e578b58ff5b06a60dd43459e9b1e9b62eb33954ff3b878e7513bfb42b51d99f4853e3e2e013e12dcb04b444caa171218f4ed13b4867c7f4130db22552e69f63dc9fb16cc8ed0c2b1876bc1da2190b53dc1e0e2fd2bc84efb023087b5fe8e39ec9d62751664d43511381d3ea31516ac0c7d6fb74403fdff6d68dc35a6a111761adadd56028ccb540c28d3181afb43392f92e325997fe519c20fecda9ab04a713927e6d622cefa0d8edf9c29fdc3f54328226a3bce63f6592e2e17b2fb1bb3079b1f7335a0ab743f9815387b7571c712e3cb5a5dea4989f32f5dd8e87c2f42da7ef9b3544d2aef2f817d3448b04306f254639afe
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92515);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2016-1263");
  script_bugtraq_id(91763);
  script_xref(name:"JSA", value:"JSA10758");

  script_name(english:"Juniper Junos Crafted UDP Packet Handling DoS (JSA10758)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and architecture, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the 64-bit routing engine. An unauthenticated, remote
attacker can exploit this, via a specially crafted UDP packet sent to
an interface IP address, to crash the kernel. Note that this
vulnerability does not affect 32-bit systems.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10758");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10758.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D45'; # or 12.1X46-D51
fixes['12.1X47'] = '12.1X47-D35';
fixes['12.3X48'] = '12.3X48-D30';
fixes['13.3'] = '13.3R9-S1'; # or 13.3R10
fixes['14.1'] = '14.1R7';
fixes['14.2'] = '14.2R6';
fixes['15.1F'] = '15.1F2-S5'; # or 15.1F4-S2 or 15.1F5
fixes['15.1R'] =  '15.1R2-S3'; # or 15.1R3
fixes['15.1X49'] = '15.1X49-D40';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "12.1X46-D45")
  fix += " or 12.1X46-D51";
if (fix == "13.3R9-S1")
  fix += " or 13.3R10";
if (fix == "15.1F2-S5")
  fix += " or 15.1F4-S2 or 15.1F5";
if (fix == "15.1R2-S3")
  fix += " or 15.1R3";

override = TRUE;
buf = junos_command_kb_item(cmd:"show version detail | match 64");
if (buf)
{
  pattern = "^JUNOS 64-bit Kernel";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because a 64-bit kernel is not in use');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
