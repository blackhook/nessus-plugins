#TRUSTED 53bbf540bed64b0e4bd2ad5056383eff2aebee795933676696c9b6aa10d541ab2dcd2f104123abd46701f2d5a07bfce2d4be7bfdfd66383c70562eb3884ece6039a0722edd0db1582b9917431adb934dde2e66687dbb574442c0452dc0691d3a14350667696d42a1a46eb3aebf131139c9448d32a3b7c995256996029364efa3b10b8964385662880f61d28d409f9cf73478c2851d03c2232237b1bd0dd4103debf93385f2a0abd54f037ff9f90f4b7fbcf2a89449b988ae15d282cf8fc52cf28ff854af30863ebbcbaa747800db994b7c336d5a481479ea67a62ae49c42a21f8359dd83fb9b52625d11aa0fca9a3b0fd0eb3d2b005c70045a6688be9223fbb3d504a9089c9c0b4121fcb714d1e8dc835747a6fe2342a04f80f635597925f7566432af8c54258e58d96df5b7660c79e197aeca61867a3e2c2df712e97b611cddf2d7970a6e89cf8a230aa63031fa23947385105e1804ae21b6ebdba7bf49ae1cc740faa7b77a4e2192c47049bee6263d7a4fc7490aa6847ebf3a975a3e7e9f688cb62f65a3c3c577eb83bbd08bbd8334ec7ba6fdc8c1797904cf74b26a4f8f25bfcc11435bd3d500bdd9c7d187eddac92e5a73487584dd3bb91f648282f88e1a7bc612c9ffe4f025c6f87a537312ae610dcc2d944e12e62e5a88043d870722ecbf80258749e59a4c45c41d7d54d108e875290a7b6d7e89c27a5e3d26b1c6975b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132959);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_cve_id("CVE-2019-0056");
  script_xref(name:"JSA", value:"JSA10954");
  script_xref(name:"IAVA", value:"2019-A-0436");

  script_name(english:"Multiple Vulnerabilities in Juniper Junos (JSA10954)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of Junos OS on the remote device it is affected by a Denial of Service (DoS)
vulnerability. A remote unauthenticated attacker can  exploit this, to cause the device's Open Shortest Path First 
(OSPF) states to transition to Down, resulting in a Denial of Service (DoS) attack.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10954");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10954");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0074");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (
  model != "MX2008" &&
  model != "MX2010" &&
  model != "MX2020" &&
  model != "MX480" &&
  model != "MX960"
) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
fixes['18.1']    = '18.1R2-S4';
fixes['18.1X75'] = '18.1X75-D10';
fixes['18.2']    = '18.2R1-S5';
fixes['18.2X75'] = '18.2X75-D50';
fixes['18.3']    = '18.3R1-S4';
fixes['18.4']    = '18.4R1-S2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for NG-RE, if not output not vuln
buf = junos_command_kb_item(cmd:'show chassis fpc pic-status');
if (junos_check_result(buf) && buf =~ "Slot 3")
{
  report = get_report(ver:ver, fix:fix);
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

