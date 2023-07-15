#TRUSTED 3c525ade953d419e6fa4920ff3551e80cbabd8a8c4e6899fad87e9f920b53a4ceedbfb1e16cf9ca17ee734313822ed839ab49f51168651772ef5ab8145f7c8bf6b1b40556080ee679300c4df89160481c3857d0476cbbf4d5f23d16be47d41624719be615c854a60f11ce090b6d4793b296a7de84d2e08a203cf5acd9ba700bda7122bf28d44d7a6bf33d55af1d52631469adc5c6fe604f06fd047957af547c4e697421fe3e9c6e45fb835070e9c4e39f2e7d2f9aa125f858159d156e1c1a9c6948674b052b5e3ae01443e9c3bbd02fbd0e3839db0e9182cb6915c9f9028239f609d4089fe7505671391a0510d107dbbe7da5e9b41709f660bfb07b0b084e4c4b9f22688ec95096afd8ce0d60540cd15a81bf2be4acc8321bfe06c7ebe584d034a681261ecb1ce4bcc5f180986c1fd8bba4322ea9db9d09de703b6abfc7762b0f06fa9e26e2877ef738c998e48d84c9572d838e899fea42f9c7a7eaf0e72aa696706536c118e91053572437a382704737072535942ecd65eb41055d19345b2f3dceccbd2a437e15160de520ff87ba99cb39b14a53520bf706eb0cf2560b575b0a44ddb71e31a50d203657ddff11d199149aefb7ede6942be1bfbed72b4ec505bb589e572c4e9437536d309eaf6747d35477a4414fa7644c0e4ba093d64d96bdae32fcd0fede487fe0d68800fcbcd0e23c48d83a2ae2294edd031c11bbed9d86f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80958);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-6386");
  script_bugtraq_id(72067);
  script_xref(name:"JSA", value:"JSA10670");

  script_name(english:"Juniper Junos BGP FlowSpec rpd DoS (JSA10670)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
improperly processing a malformed BGP Flow Specification (FlowSpec)
prefix. A remote attacker can exploit this issue to crash the routing
process daemon (rpd).

Note that this issue only affects devices with BGP FlowSpec enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10670");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10670.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
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
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['11.4']    = '11.4R8';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R9';
fixes['12.3']    = '12.3R2-S3';
fixes['13.1']    = '13.1R4';
fixes['13.2']    = '13.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "12.3R2-S3")
  fix = "12.3R2-S3 or 12.3R3";

# Check for BGP FlowSpec
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols bgp group \S+ family inet(6)? flow";
  if (!junos_check_config(buf:buf, pattern:pattern))
     audit(AUDIT_HOST_NOT, 'affected because BGP FlowSpec is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
