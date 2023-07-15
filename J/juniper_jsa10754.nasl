#TRUSTED a50f11a19e66ae6dc39fa75cad91b53955c2fb7b2b5c4849efae70ca7f0b4bb247af9578d4acee24e1bc4cfd4674ae80ee639794633160070263eb126b07d6bc4c45ab7ba8ea790182b8e04a3dd6275eb1fbba2490ec0de7b2d52fb4d8a85be4678077c847bde87f28c87b8146be316949fac7a7f77d3f0fe638a5c796410eac7518b7ce29e5c448dff02ec953543c789bba684087ee5b15581bad115c28352c352f2cd7b684ea402a3fdd9c08693595620f86a0090a2ba94a3592a9d65cc39de8c36ad515caca2b23db9d66ea2118b60b2eb3af3d02b7aef3b05c596ee38a0f036657b85abc0230e119e765d92512886d0ff80c2eea336bb22f56b0afbd1ddab1c1b30d3e6c73353e399119f59fe44c21f33af40015245b89058e6e4feb3d60aa9bd4ad277094284e31d3085ed97afba7682e8efb650e957d828b92f599940307581b5539a7c3ba42d581b8c6d87a6abc7f847dd33aa8d5e7d58d355203e6e95f73ba5bd83b1ec9c1e80e12ef90d2ee3cd0ea91b8791ede329113c19e39653d3f8f6170b86eb16033e92c3a180b7a5704efc58f200be9efa6df9a0d6b1fb3f8ba8c5a29877550157306110cc8ec63c12ad55839b9687ba067ed2846ed6a9ea89a65ab1cffb0af704ae51a721d26a5d2d6ac0817eb4cfdd38f944fde4d0797d662b2d18b5522493545b6dfd0ed6fb3351838805c9811e58e446138ed4981db70
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92512);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2016-1279");
  script_bugtraq_id(91759);
  script_xref(name:"JSA", value:"JSA10754");

  script_name(english:"Juniper Junos J-Web Service Privilege Escalation (JSA10754)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a privilege escalation
vulnerability in the J-Web service that allows an unauthenticated,
remote attacker to disclose sensitive information and gain
administrative privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10754");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10754. Alternatively, disable the J-Web service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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

fixes['12.1X46'] = '12.1X46-D45'; # or 12.1X46-D46 or 12.1X46-D51
fixes['12.1X47'] = '12.1X47-D35';
fixes['12.3'] = '12.3R12';
fixes['12.3X48'] = '12.3X48-D25';
fixes['13.3'] = '13.3R9-S1'; # or 13.3R10
fixes['14.1'] = '14.1R7';
fixes['14.1X53'] = '14.1X53-D35';
fixes['14.2'] = '14.2R6';
fixes['15.1R'] = '15.1A2'; # 15.1R3
fixes['15.1F'] =  '15.1F4';
fixes['15.1X49'] = '15.1X49-D30';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "12.1X46-D45")
  fix += " or 12.1X46-D46 or 12.1X46-D51";
if (fix == "13.3R9-S1")
  fix += " or 13.3R10";
if (fix == "15.1A2")
  fix += " or 15.1R3";

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the web-management service is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
