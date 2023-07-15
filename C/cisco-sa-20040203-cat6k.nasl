#TRUSTED 8d9b900157010dcdefb6f98f7c660be0968740d0d4b5e4788ccf3158281ffc0715d10c6a1592efab40a331236a3d53ca6c92ba1e8ea63a2614858cd7a1f75efa90fd390fef123545c635ad831016aabbe03754ee4ab76fc220274d2379dec5871cd0c3feadbbbef4686545bb684f7c01d611640edc04512dabb3ad80b83cd61bf0fe6c726a64baf91fef510da36f3e46e0164cc804439e838e9dc83c57decce60f764cb7cc1829a2b20da8f5aa23663591abe74cab894c465dff21e1abcd089cbe772f60e452cee8f7847b1ad3a17488bc89b0e4617d49eb2bc9750e3bc2190222399a29eb6ac8a6fd13373126ce016d3d7209957c01ea601f1b60d3cb8ba0fe5b40390e5ac8e4e8f3e0c8af43b8efd381d5a9957040ee5029051ed2c2afb58b48940cf14ef5423898a6f11ef1912088faf8e5ce7c134f5ef6c42fdcbc044834cbe1a52fe84ddded8c8b1e19d047fdf81beaa8df772d6d3c8dd3dc096b4e5dc1bb8417cf969b5a48835a4a727c38bbebf2efe600bfc6b474acf6a21899b04531f9c5ff866b49d3383a950e4c3cde0d1863849b415c6793405805f938a66b4cc345c46f1e8a2805ca575266b1e6cb03d8d91f2c11c8b393816199fe4bf901cfe86859468b2d86e9c9b61995e5b08c87dd213532725e08a16a3ae4395446f382d506f0d4ba7e377c33ea11071891ccd5cbbdc097016065b3f7218177a1198c8148
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00801f3a8a.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48973);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2004-0244");
 script_bugtraq_id(9562);
 script_name(english:"Cisco 6000/6500/7600 Crafted Layer 2 Frame Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'A layer 2 frame (as defined in the Open System Interconnection
Reference Model) that is encapsulating a layer 3 packet (IP, IPX, etc.)
may cause Cisco 6000/6500/7600 series systems with Multilayer Switch
Feature Card 2 (MSFC2) that have a FlexWAN or Optical Services Module
(OSM) or that run 12.1(8b)E14 to freeze or reset, if the actual length
of this frame is inconsistent with the length of the encapsulated layer
3 packet.
This vulnerability may be exploited repeatedly causing a denial of
service.
This vulnerability has been addressed by the Cisco Bug IDs CSCdy15598
and CSCeb56052.
There is no workaround available. A software upgrade is needed to
address the vulnerability.');
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20040203-cat6k
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a7aa89a");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00801f3a8a.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?89a5ecaa");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20040203-cat6k.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/03");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/02/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdy15598");
 script_xref(name:"CISCO-BUG-ID", value:"CSCeb56052");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20040203-cat6k");
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

# Affected: 12.1E
if (check_release(version: version,
                  patched: make_list("12.1(8b)E15", "12.1(11b)E14", "12.1(13)E1", "12.1(13.5)E", "12.1(19)E") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2SY
if (check_release(version: version,
                  patched: make_list("12.2(14)SY") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2ZA
if (check_release(version: version,
                  patched: make_list("12.2(14)ZA") )) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"WS-X6182-2PA", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"OSM", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_warning(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
