#TRUSTED 05da063ac13b845e91fb9d054c92525fb014b17e615aa9ad95cc14e2dce34bc7707ca5670549cb18a743c2eaab54cd8d000ea64ff65bc03fe09ec8a5f6bc97dbd1b650aa6b2800e80371e8e5012ec72548ae9adc529481658733030978ca12fe4307fa9c27d799e92461fb91557d3c03a4850c3f27c756b61a80b02f4791457f345f8624064a0086c38c39986f7f468b12525dab656b6d6875c8eb4a5d5ed0a5587669fd3652f376a02f6fa04d3e808a2fd9e7cb352a338a8a79bfdda2553760f860d8c8215e59fd09975235a6b5610f2a6af4c6d8a0f3914b16a1ebfb399dd2bea4d9da7b98d656204861b809c0fe08d3a4ff414131e43462cbec004213d44bf8ced264c894e1c9879e0343e282226c691a31188bae4ec783ab01fd69c4de772c23b7b229fbc5a5cb6622305a8184dab46190f99b81a2a2759b16c89f306ed4d0a7cb1427936d3b66c39e31246096ef6d0316de20eaa2cf33b34edb2e1ca01c6c1b36b07ce4709a2f7c50d4136cae90016a10e9d3c32a1919bf55018b8daad522d97fcae45ca81530a6a0e6d9c3c4b904a8c455b80e09ce2d5665de78e049664bb84ba0617599f33004e0b1741ae212dce36860d33232e20f27082639e1a3a64f3d478655f496d18c2c7d62d43fa38e0acf6aa21313dbbbf18014d2e38f85589f0eefc9c0d4c4cb5ef9ace8bec2536981a02e846fd329c87f898c8ea5d5bfaf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92519);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2016-1276");
  script_xref(name:"JSA", value:"JSA10751");

  script_name(english:"Juniper Junos SRX Series Application Layer Gateway DoS (JSA10751)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the application layer gateway (ALG) that is triggered
when matching in-transit traffic. An unauthenticated, remote attacker
can exploit this to cause a denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10751");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10751. Alternatively, disable all ALGs.");
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

fixes['12.1X46'] = '12.1X46-D50';
fixes['12.1X47'] = '12.1X47-D23'; # or 12.1X47-D35
fixes['12.3X48'] = '12.3X48-D25';
fixes['15.1X49'] = '15.1X49-D40';

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "12.1X47-D23")
  fix += " or 12.1X47-D35";

override = TRUE;
buf = junos_command_kb_item(cmd:"show security alg status");
if (buf)
{
  pattern = "^.*:\s*Enabled";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because no ALGs are enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
