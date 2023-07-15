#TRUSTED 8498d48427f80233fd1d189c4743f154b7c97b39ac5e65baccc9f6c46625898cdbabb0fc9655e712bc041d4fe1f6fd1f9411c998798cb3b3add27182a78449f9cd9bd78905e1e4664bb45972d488c9e7a9aba2398b0e20540eccfc9b739eb4201429ffb7245b5049541b072bcddf52ec94ff19f955993f849ac36c1477becb1b37336b88a7330f35f4559f95822ab5bcd2c1e2bb0937aac0159810c90590853c5f3c6af80b47531466386bbdf1a20df2d72c17e68a49317ab0c9485821a99ae66f8b8ef216d36b14ca1de8e1db32477a615a710464d7ef41471d6b91621421af3ee84c1c5d2477a521c82969c18da306d7f7017ff01a7f391c730089e7ec986b760e49ec139ed9d9815811dd4efad72b9156ea6ce72b52f82804a615c7f28e1e1c9b228e6a1c5e5ebebf9877b9cdbccbd3a6eaf573cf93552d53509b392aff938dd7b37f3f8042899797f672072a7357571848b24676bccc91deb9b2503edfcf047f3e1f4672fa035d9c577dad1a1585b8a323113797322b69f1b3b4756235a7928f3ed541547b48cddcb55df11279bb2d345b19f3b3c6719b004c03ec76938fb6b427541cbcb0e0139b62881084399c04fd7b60016957d8415a4f53f3dcfddee27b2ddb9c9a6dbeb9e62131f865284bcf38168ab7d6ca9813497157e4dbc0307479e4efc60f9415d3ea81cbf742482c8abeaca8978670d7cffb5fcb51b8d4e0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86477);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2014-6451");
  script_xref(name:"JSA", value:"JSA10700");

  script_name(english:"Juniper Junos SRX5000-series J-Web DoS (JSA10700)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX5000 series device is affected by a denial of service
vulnerability related to the J-Web service. An unauthenticated,
remote attacker can exploit this to cause the system to drop into a
debug prompt, effectively halting normal system operation.

Note that this issue only affects devices with the J-Web service
enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10700");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10700.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

# Only SRX 5000 series
if (model !~ "^SRX5\d\d\d$")
  audit(AUDIT_DEVICE_NOT_VULN, model);

fixes = make_array();
fixes['15.1X49'] = '15.1X49-D15';

# Specifically D10 to D19 of 15.1X49 is affected
if(ver !~ "^15\.1X49-D1[0-9](\.|$)")
  audit(AUDIT_DEVICE_NOT_VULN, "Juniper device", ver);

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for J-Web
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management http(s)? interface";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because J-Web is not enabled');

  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
