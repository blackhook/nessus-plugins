#TRUSTED 571685322f55889e539b8927ab279ab4b4a79a062fb50d77da30d44ee227910d28fb47f3f9547a8661cd5d359de52354233fcb544946adc96f5eea837566057e4790bd2c11d744c7f537ddba23557fb622ec550b5adb7af5d591f65bc075e29cd724d1ad42096df1a88d9b5794221b5e8f7f85de636063f34352d3834887317955a1f17f14d3d33b7c431312bbb8a07c4d4655da6c39062874c83ea6f53715e502b5ea9f7d9c2036238ffd66b9fb0728e925f2eb45b415fbd3563a731903395da6bf108dca5a2e96dc22756261a943340cd686e81b1b2dd440d8d4b5f5429e5c0bf604d04900f5dde1ac10e67241116708eb0754ca05f5c3c224edfa4004b53692ec5f46156c7e8b96a1e0368267e70e0177a466620a68959212500760fe163676777b980a5ec2bcd95706be2e90aebd6c9df0d70848bbbe5da3e771b49eea0441a7c1687826f0a4565183cec511edd746e40c6e665bc85292d52a96aa234ec7b9d35ed758922f5306c7cc1f1d1dce1937526ce90c5362e9cf2cc85acccce9ac2bc67af59a58be57bae2c0d5cfa0354cb9fd4c0c11e1e70fd05849362d2deff25c3ba8e8ec170a93096ccb7803f9361d85ad16216d379aaf5fc721e4adb4513b555e1360df40c3a3b4553393e6ee1d701b0afb46b5e901feab0023c2c9b1dc7024ba0dc0817b1e894d69fb71993df40ce64bc5eb366b2b4eb04740fa83a3d9dd
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See http://www.cisco.com/en/US/products/products_security_advisory09186a00807f4139.shtml

include("compat.inc");

if (description)
{
 script_id(49002);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2007-1257");
 script_bugtraq_id(22751);
 script_xref(name:"CERT", value:"472412");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsd75273");
 script_xref(name:"CISCO-BUG-ID", value:"CSCse39848");
 script_xref(name:"CISCO-BUG-ID", value:"CSCse52951");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20070228-nam");

 script_name(english:"Cisco Catalyst 6000, 6500 Series and Cisco 7600 Series NAM (Network Analysis Module) Vulnerability");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"Cisco Catalyst 6000, 6500 series and Cisco 7600 series that have a
Network Analysis Module installed are affected by a vulnerability, which
could allow an attacker to gain complete control of the system.  Only
Cisco Catalyst systems that have a NAM on them are affected.  This
vulnerability affects systems that run Internetwork Operating System
(IOS) or Catalyst Operating System (CatOS).

Cisco has made free software available to address this vulnerability
for affected customers.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f70509a2");
 script_set_attribute(attribute:"see_also", value:"https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20070228-nam.html");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20070228-nam.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report_extra = "";
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

model = get_kb_item("CISCO/model");
if (model)
{
  if (
    model != "ciscoCat6000" &&
    model !~ "cat600\d+" &&
    model != "cat6500FirewallSm" &&
    model != "catalyst65xxVirtualSwitch" &&
    model != "catalyst6kSup720" &&
    model != "ciscoNMAONWS" &&
    model != "ciscoWSC6509neba" &&
    model != "ciscoWSC6509ve" &&
    model != "ciscoWsSvcFwm1sc" &&
    model != "ciscoWsSvcFwm1sy" &&
    model !~ "cisco76\d+"
  ) audit(AUDIT_HOST_NOT, "affected");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS/Model");
  if (model !~ "6[05][0-9][0-9]" && model !~ "76[0-9][0-9]") audit(AUDIT_HOST_NOT, "affected");
}


# Affected: 12.1E
if (check_release(version:version, patched:make_list("12.1(26)E8", "12.1(27b)E1")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.1EX
else if (check_release(version:version, patched:make_list("12.1(12c)EX", "12.1(13)EX")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2EU
else if (deprecated_version(version, "12.2EU"))
{
  report_extra = '\n' + 'Migrate to 12.2(25)EWA7 or later.\n';
  flag++;
}
# Affected: 12.2EW
else if (deprecated_version(version, "12.2EW"))
{
  report_extra = '\n' + 'Migrate to 12.2(25)EWA7 or later.\n';
  flag++;
}
# Affected: 12.2EWA
else if (check_release(version:version, patched:make_list("12.2(25)EWA7")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2IXA
else if (deprecated_version(version, "12.2IXA"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)IXB2or later.\n';
  flag++;
}
# Affected: 12.2IXB
else if (check_release(version:version, patched:make_list("12.2(18)IXB2")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2S
else if (check_release(version:version, patched:make_list("12.2(14)S3", "12.2(18)S5", "12.2(20)S")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SG
else if (check_release(version:version, patched:make_list("12.2(25)SG1")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SGA
else if (check_release(version:version, patched:make_list("12.2(31)SGA1")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SRA
else if (check_release(version:version, patched:make_list("12.2(33)SRA2")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SX
else if (deprecated_version(version, "12.2SX"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)SXD7a or later.\n';
  flag++;
}
# Affected: 12.2SXA
else if (deprecated_version(version, "12.2SXA"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)SXD7a or later.\n';
  flag++;
}
# Affected: 12.2SXB
else if (deprecated_version(version, "12.2SXB"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)SXD7a or later.\n';
  flag++;
}
# Affected: 12.2SXD
else if (check_release(version:version, patched:make_list("12.2(18)SXD7a")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SXE
else if (check_release(version:version, patched:make_list("12.2(18)SXE6a")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SXF
else if (check_release(version:version, patched:make_list("12.2(18)SXF5")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}
# Affected: 12.2SY
else if (deprecated_version(version, "12.2SY"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)SXD7a or later.\n';
  flag++;
}
# Affected: 12.2ZA
else if (deprecated_version(version, "12.2ZA"))
{
  report_extra = '\n' + 'Migrate to 12.2(18)SXD7a or later.\n';
  flag++;
}
# Affected: 12.2ZU
else if (check_release(version:version, patched:make_list("12.2(18)ZU1")))
{
  report_extra = '\n' + 'Update to ' + patch_update + ' or later.\n';
  flag++;
}


if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
    if (check_cisco_result(buf))
    {
      if (egrep(pattern:"[ \t]+(WS-SVC-NAM-1|WS-SVC-NAM-2|WS-X6380-NAM)([^0-9]|$)", string:buf)) flag = 1;
    }
    else if (cisco_needs_enable(buf))
    {
      flag = 1;
      override = 1;
    }
  }
}


if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
