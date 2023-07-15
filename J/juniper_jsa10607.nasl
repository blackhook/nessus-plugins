#TRUSTED 09dc13e1b8a5550a8da8f89ea82c7b0342709aacf7164ce9cf3450cb540042e5b2ff6e0b0a0959b36a2df9420087b632de1916b693a0c01cff5388fbba225b0ecf0b8e68c546e637aaeb81d2435d405a53d0dfeb830c6dad319b4abc0e5b443f95e49ca5f4ccf949abbcff0c7b078a52b8636a4d860304eba880b56c7191a580d340ff5abdf63f3a85cb6d2bbe59da87857b53807fbc938dfac0e687fd7563615ddcdb147ba098b78ddd82fcdf299331ba64d9c0c054dfd2b9dcf421e75975b1af9b36eb975266d4a3af6632ffcdaed839cc0233442c33d555784a17452442c9cc075e8be6525fbca88f38816e1648703a56db1da5975cfd1694eeb61608d65d07d470cf4880122809cba07d7f23a6690de865a9011f26a6d47753d9086e2563839af38a4e5a79b908f7c1a3fc2fd348b36463bc61a32e68b42779a0f3b69b8ba08bb77f8553321a16dae7f513a33951b6f800e95c52ed75e07bc036bd76f01c90015348a7d6dd6a9712b2caad8469db900ff34bbda6b33f57530a475792a0d09d97d8dfcc10867f17ed3d033225c9c793364cbd7f570624874e09ef953b313686922df1ee280b712d4cc0d7dce4ca1c88d7c5d31b861752775d3e5387cfe18db19f3348907c7fe92224d7d7edfedf8578118c0b0988f60d3be6aefd978e11e896dea187a5334238ca4606f4fdf790918a0100bb79f4cba05b0c867883746f92
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71996);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-0613");
  script_bugtraq_id(64988);
  script_xref(name:"JSA", value:"JSA10607");

  script_name(english:"Juniper Junos XNM Command Remote DoS (JSA10607)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability related
to the XNM command processor. A remote attacker can exploit this to
cause a denial of service by sending a specially crafted XNM command.

Note that this issue only affects devices with the XNM service
enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10607");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10607.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-12-17') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '12.1R8-S2' || ver == '13.1R3-S1' || ver == '13.2R2-S2')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['10.4'] = '10.4R16';
fixes['11.4'] = '11.4R10';
fixes['12.1'] = '12.1R8';
fixes['12.1X44'] = '12.1X44-D30';
fixes['12.1X45'] = '12.1X45-D20';
fixes['12.1X46'] = '12.1X46-D10';
fixes['12.2'] = '12.2R7';
fixes['12.3'] = '12.3R5';
fixes['13.1'] = '13.1R3';
fixes['13.2'] = '13.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# XNM Clear Text or XNM-SSL must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services xnm-(clear-text|ssl)";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the XNM service is not enabled');
  override = FALSE; 
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
