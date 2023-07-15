#TRUSTED 5a59a8b51f69424250324c6dc3c907c7d7763d20529758ad81484d99a82febf9df990c0c7015acad26ee23c4b5801a312fb9c8e8ae812af93e1b49a006447ac6771900c75b6e46f5521e64ef74049ea1e8b3970a7c7ffe7a1bf1c6963262e37b427267caa0b0eb829d65777b3a6580d86a6ca69d8d30ef7518b7f03a99a8f61a6e9b2d694ee5dd5ed5a20830dbf19b25901f321cfacf3694a03e3382586365ad991d93cb267917a6de613a6148867bb456091dedddf1e023a2ed39feb6b33a01b43312ece9c694a20ec58713fa9e9c3e47ea96ef0d2a05148cce4a2dc9cdeb6733b838d9abac6c44218c35b69e2d11c31c810200d1cf15472cb8199e46a635d06abd2dd484c0571eedce4adf304eb51228baddf23ad8060e3aa060edd0f76374cd5265f414426e5b405b727ade83296dbbccc50d8abf94b78121be928558c16844ca64988ddb4b3e5546d173eec6d25fd3578e9d572042d412b5381e3faf54bd8feb793660f0093cf7e854dbc9bc7e623e5aafcdfa1d6c118e7276955caff83fd8d67818f71c0c4d20a7c79a7bbb7e25606bc49a4da45a75a98e65243766ca3e6a727d9b871286b5063d04db8fa3856ccec2402f7db745f32eac5b494301757165207259fe97bafc6694a5eb0aa8f38157ab1cb6edde144cc692100bfef69178d3053129d0354731f649f53821fd81d0d56df5ce889b84a4ba74c63d3935aebc
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20131023-iosxr.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(71435);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2012-2488");
  script_bugtraq_id(53728);
  script_xref(name:"CISCO-BUG-ID", value:"CSCty94537");
  script_xref(name:"CISCO-BUG-ID", value:"CSCua63591");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz62593");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120530-iosxr");

  script_name(english:"Cisco IOS XR Software Route Processor Denial of Service Vulnerability (cisco-sa-20120530-iosxr)");
  script_summary(english:"Checks the IOS XR version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description", 
    value:
"Cisco IOS XR Software contains a vulnerability when handling crafted
packets that may result in a denial of service condition.  The
vulnerability only exists on Cisco 9000 Series Aggregation Services
Routers (ASR) Route Switch Processor (RSP-4G and RSP-8G), Route Switch
Processor 440 (RSP440), and Cisco Carrier Routing System (CRS)
Performance Route Processor (PRP).  The vulnerability is a result of
improper handling of crafted packets and could cause the route
processor, which processes the packets, to be unable to transmit packets
to the fabric."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120530-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c29bbd37");
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120530-iosxr."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2488");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
temp_flag = 0;
report = "";
override = 0;

cbi = "CSCua63591";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ( version == '4.0.0' ) temp_flag++;
if ( version == '4.0.1' ) temp_flag++;
if ( version == '4.0.3' ) temp_flag++;
if ( version == '4.0.11' ) temp_flag++;
if ( version == '4.1.0' ) temp_flag++;
if ( version == '4.1.1' ) temp_flag++;
if ( version == '4.1.2' ) temp_flag++;

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"Route Switch Processor", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}
if (temp_flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + version + '\n';
  flag++;
}

cbi = "CSCtz62593";
temp_flag = 0;
if ( version == '4.0.3' ) temp_flag++;
if ( version == '4.0.4' ) temp_flag++;
if ( version == '4.1.0' ) temp_flag++;
if ( version == '4.1.1' ) temp_flag++;
if ( version == '4.1.2' ) temp_flag++;
if ( version == '4.2.0' ) temp_flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"Performance Route Processor", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}
if (temp_flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + version + '\n';
  flag++;
}

if (flag)
{
  security_hole(port:port, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
