#TRUSTED 7835874be57d33246ef48085a5e4daa57e7ede06d0ad1d88e33b3f378ae616e325a60821072132d7bbaf3e3d831f56f0e65ff23928df004b67179d9a9bcd25ca27de116da868607ae95add728c7154b404ca1471abc3ef62922ad38557ec374bdc4ce19b8edce0f9ced754195af876da26737962df55f5c73702fb118bc7e87d37d8c696eb3f71b8d133dbe53a6ecf387c8eecfba99acfa2bf4308ab1af7ec8514ac400841622cefd61cb59221818230ba152c3dbf60b1da7390c20bf68700349314b8284609e7391382f13ca5b806d50d9bc425c5241141ccc2ff5cddbe22d2f266280429bc54e1b5bd3d2bff7d1bab992fa636fd34944a41d60b997a6947965c233738ca22ab7b3e53b2362a0b2bcbcf5a323e2f39db41a258c73f677d14548e5d0872b7e5b09ac001ddf442a97400bd2319c0ec5fbab9a39cc0786c3dd99630cc9a216d3b08db6af90f158f38a484c78c527196ad6d74b6d42b465036bc27b48a3d5d8b1766a3fbe5df85226aaf5d7f1bc5479273fdade261e591997f70c2687db85a63353494625c9cfd9ace0c8dfa2cb71440e54a75f5b55e1422d8e372b176b05e60745e4ec1ba3b4f349961fcd102399633c6f3a66ac6bb0a43e80a70a6eff5bc9b5ea16058f41deabb7b2a46aa0342e42eca76e892dc97dad381fac7846e4259c5e967ed0c78c739197d8e6524702f9537395b7ac8b265e4c9ce4855
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78426);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-6380");
  script_bugtraq_id(70369);
  script_xref(name:"JSA", value:"JSA10655");

  script_name(english:"Juniper Junos 'em' Interface Fragmentation Remote DoS (JSA10655)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability. A
remote attacker can exploit this issue by sending a set of specially
crafted fragmented packets to cause the 'em' driver to become
permanently blocked when trying to formulate a reply.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10655");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10655.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

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

check_model(
  model:model,
  flags:EX_SERIES | M_SERIES | MX_SERIES | PTX_SERIES | QFX_SERIES | SRX_SERIES | T_SERIES,   exit_on_fail:TRUE
);

if (model =~ '^SRX[0-9]+' && model !~ '^SRX5[468]00($|[^0-9])')
  audit(AUDIT_HOST_NOT, "SRX5400/5600/5800");

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['12.1']    = '12.1R9';
fixes['12.1X44'] = '12.1X44-D30';
fixes['12.1X45'] = '12.1X45-D20';
fixes['12.1X46'] = '12.1X46-D15';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R8';
fixes['12.2X50'] = '12.2X50-D70';
fixes['12.3R6']  = '12.3R6';
fixes['13.1']    = '13.1R4';
fixes['13.1X49'] = '13.1X49-D55';
fixes['13.1X50'] = '13.1X50-D30';
fixes['13.2']    = '13.2R4';
fixes['13.2X50'] = '13.2X50-D20';
fixes['13.2X51'] = '13.2X51-D15';
fixes['13.2X52'] = '13.2X52-D15';
fixes['13.3']    = '13.3R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for CLNS routing and ESIS
override = TRUE;

buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set routing-instances \S+ protocols esis",
    "^set routing-instances \S+ protocols isis clns-routing"
  );
  foreach pattern (patterns)
    if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;

  if (override) audit(AUDIT_HOST_NOT,
    'affected because neither CLNS routing or ESIS are enabled');

  # 'em' interfaces are the only affected interfaces
  buf = junos_command_kb_item(cmd:"show interfaces");
  if (buf)
  {
    pattern = "^Physical interface:\s+em[0-9]+, Enabled, Physical link is Up";
    if (!preg(string:buf, pattern:pattern, icase:TRUE, multiline:TRUE))
      audit(AUDIT_HOST_NOT, 'affected because no em interfaces were detected');
    override = FALSE;
  }
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
