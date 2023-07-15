#TRUSTED 577a0137b0619966928c4e53afdcf4b38d56af611b9008f7dd84b7dbe29343b0e3a9e6e6978744b91d46519ac03050777335c88203b262a127e26ab8f01f945378c3c627503e2a2d3b42c618625bdde700a41b4fef316bf64f3315d710127a8e19866ba82821b6ee062377173d30b57179515a5b2f4cf3d82643fbcf5ae908f601291898ab047683b7b1f4dd75e554870b9b9557b1249a35b710e9f174c3dac720c21767f6e4406621652bf2ba0c3f9338c6e4f820969f22ad50b230a47fe6759fd5c939fd91c57020a73d38a873e0fb3828295abe4547a170f3d6a4a1080c2694c08e8be04d21b8088942dea8054627c3fde5e29ff5198ec74e102060af36e9cc0750d24faa53192cc7d1c43251b81f823fe14fa4955fdf9e49ec6e9d3fa8965604d5287a9aa12d5de53bb1402066a5201c3f4114f3260cebbab6e2b8e65b6e860f7f7c2f0924d3aa5fc3566cbec6118d1a6e2f50ebac12e57855ac692c307d5b162e95fd5ab7c2919fdcb1e8d6ea70bc1bcbcc68d4abd434079c3c66c0a0df144224ab826b412c1d83eb350b66472050772bbe16b0fafc073161a0df12c876b10fe725368ecc76bdb466f2c21a989ae93549eaa38659101a7926714781e686fe263ea6eadb99de93640eb04630ecce178f12fa285050796be33d4551cdc69b3b326b4e1072813d75e8fc75e45137fb452526783b7a27f17650a7d1c6fb126a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85225);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2015-3007");
  script_bugtraq_id(75718);
  script_xref(name:"JSA", value:"JSA10683");

  script_name(english:"Juniper Junos SRX Series 'set system ports console insecure' Local Privilege Escalation (JSA10683)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX Series device is affected by a privilege escalation
vulnerability related to the 'set system ports console insecure'
feature. A local attacker can exploit this vulnerability by using
access to a console port to gain full administrative privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10683");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10683.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (ver =~ "^12.1X46-D([0-9]|1[0-4])$") audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['12.1X46'] = '12.1X46-D35';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.1X48'] = '12.1X48-D15';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system ports console insecure";
  if (!preg(string:buf, pattern:pattern, multiline:TRUE))
    audit(AUDIT_HOST_NOT,
      "affected because the 'set system ports console insecure' feature is not enabled");
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
