#TRUSTED 4df3842aa96a63135786f7100594191c39b4ea00865d8eedd1cccae2566ca85962b4b7b686aebba5db7e92736a663db44df56f661ea7005aa29ed381164bc90beff019f645158768f0d01dea90b696632c0b7b4206d8c99d9c48df4bf23aa38ee06929a15dbd8789ee5bdc5fa44d9d02009f7091c4e5d71139cd0c253d2497651dca2185d48f51d084541e3204e633cf1add7fc10c7dd61282ff80d1243b6368287f5f8256d1373abe03d06686300c9c39c5f7dbe378a13ec89fbadaf39a315b3e3c842722f0465e31f196bbc65a02a95aeac7a63f467c63e02bac78f8b3470c0c18d86cac0c3a75ea2838989e54a4a41d7d5992ace07d32388ecaccc36e1f48d6aed2a4860154e9be0f7235b53418528b2e2dd5bdb4ace737e19a16fcc3823d5f6fa29a731bd6be832875f4f3afe85bed8acc41ee310bc62c095ba93a8467d9124514088c48f4bc93ab653ff71a0408b2e5aa3202c2371294ac4875f7cf1f375ddca2a55f6692ba476a918857138841f4454d47ee39efbe23c3a5daf942a8dac8d45f1e2ef70a6f118db774acc39ee1e380f274046b97aefc4eb005f6144eaee58565186988525799eb6101cdc6d940e0d57872208349135353a3f798cbf61d1febcd714362880e5ffb4b7be5aa0927e9aebfcd01ac9e5499810f4737e02befe78ef43c3bcb27f378784b7c5cd8dafc8d0acae0e65d16e5f187e4ad6ceb1953
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00806cd92f.shtml

include("compat.inc");

if (description)
{
 script_id(48993);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

 script_cve_id("CVE-2006-3291");
 script_bugtraq_id(18704);
 script_xref(name:"CERT", value:"544484");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsd67403");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20060628-ap");

 script_name(english:"Access Point Web-browser Interface Vulnerability");
 script_summary(english:"Checks IOS version");

 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"The Cisco web-browser interface for Cisco access points and Cisco 3200
Series Wireless Mobile Interface Card (WMIC), contains a vulnerability
that could, under certain circumstances, remove the default security
configuration from the managed access point and allow administrative
access without validation of administrative user credentials.

Cisco has made free software available to address this vulnerability
for affected customers. There are workarounds available to mitigate the
effects of this vulnerability.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff6a35b0");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00806cd92f.shtml
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbeb9f97");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20060628-ap.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(16);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/06/28");
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
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.3(11)JX1') flag++;
else if (version == '12.3(11)JX') flag++;
else if (version == '12.3(8)JA1') flag++;
else if (version == '12.3(8)JA')  flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_http_server_status", "show ip http server status");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"HTTP server status: Enabled", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"HTTP secure server status: Enabled", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
