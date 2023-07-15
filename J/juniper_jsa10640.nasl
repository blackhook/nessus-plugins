#TRUSTED 421d401610e6e9586abfce5aeac2bdfb97f87324742ed39a0179309d3cf9f3d52b5e77f18da05c314cbb144b4926bfb94c149387dc5b80d52c07da8d572186f60062f349cbe7272595faeff4084167615ed3bbb20991faefdeb0ddb3e50d92c98bdc31bee1f5f99b3a7b56fe2104dd5040a903908677fa2c63e403df3e63b0db6f70bb7723f7b53cdee81b6d9c52bed91b2dbe52a9ed3b36c1c72f9a87e2c23a5eb1c9ee384d7640d9e699ecc85b207fb5d27fc805c25823fe2dea281c3b8ad33d19f8a5f3bebd10432005fc31a52a28881a65144d7db32b4f44085d6e242fedf5e988ad2d6dfd18051c6aeb68b7a4c47a4f80bdacabeae9b218268c4b59b9d5b62b1ff33e9190dcc35892a0c4e4a785233afa5b2de8d550a4ce655d02761e5d70c4381b006afeb8d9c1adb46497cd8e82db6d6fc5a32e43ca7ccdcb627025ee77f9ebe448f57f1b9d84838c9ba4ddd9e9c732d3e103b11d07c31e6dd96d19af2f2614c50017acbd69da1a564f0b08b89d14a9e2ba9ff97efa67afad745d6a5870a1376fd648f0a7853ce2a82b07a8e81317237056246d6da2c8ac4c3ec3f08fc6ad8e26fdef4b3f52c1232a823ae4bbba34d948502be59a671e8f3eb499cd95fd6df8cb1da5b5597d19f176b439925ce405d2e55fe326e90be29e89d4ed9a5c2b131a20c72d162136bfbfedf090705449909aa15bb1d5a8cb92f9513faecf51
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76507);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-3821");
  script_bugtraq_id(68548);
  script_xref(name:"JSA", value:"JSA10640");

  script_name(english:"Juniper Junos SRX Series Web Authentication XSS (JSA10640)");
  script_summary(english:"Checks the version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a reflected cross site scripting vulnerability. An
attacker can exploit this to steal sensitive information or session
credentials from firewall users.

Note that this issue only affects devices where Web Authentication is
used for firewall user authentication");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10640");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10640.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (ver == '12.1X44-D34') audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Web Authentication is used for firewall user authentication
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set interfaces \S+ unit \S+ family \S+ address \S+ web-authentication http",
    "^set access firewall-authentication web-authentication"
  );

  foreach pattern (patterns)
    if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;

  if (override) audit(AUDIT_HOST_NOT,
    'affected because Web Authentication is not used for firewall user authentication');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING, xss:TRUE);
