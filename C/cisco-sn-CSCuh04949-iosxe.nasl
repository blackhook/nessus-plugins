#TRUSTED 30fd0eacaa475acc16518c5ba5111e25f2312f7cb8b929a6ab96b0d70355d9475663ee8a7e555c213a57e0876dc58b595479cd4a49e02434ca4e771a363dc71474a9fbe8840c619e5f9e082bbee134039099f02b552d970f113a5d0e6e32f97ba995737ef16cd95230ff71a9981679ea1ab96c87a9589df5db7f6fbe07fc5f45bb6b93e3f86d4aa66e387195fadb72a9fb02cc1ce0b9fb7be36bb2dbab905f327c48fc92079a02493b92b222f931029165d2a2eea72dcf780a4c868fa8de32da3f794c2bbcd232361be17af25de0d7a58914d8733600ad256dae2ab96cf0c0a493b1a894feb4e44c95207f5f3dd0ea6fddcf72af99ec29915a274ec73073a00e86a9cb685c45a84dc82cef8a045366414886659cde6ebea8961d8ece1e3c9eb9742b98452e9faa04b9beb9bfcfba12a0031a5c3d8f546ac58d6da8b9dc25cac2d12050e3496cbcd40ece8e4389fc73714e2d5be0049f970544cc339f9a6e233dca1e392f251454fe5293525dc3e81795f40c51ffd7cc223ad84d2932e104918b2fc963210429fb2601c1729a2ea38f681da73a18abcc6ee8357c91b31b483760f677a48e03c250c70e75c232e509d6c91162fa3998a46c7c1aca6c6644c351ddd3b4776b9b412c10d31569af462e2f38005c103d47129d7759c954c390f9134f6abcc1db510b94f11fa8411f5220fb5f5b6bf5a6aad84efe3d3be0116dbd6ef7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76882);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-6692");
  script_bugtraq_id(63855);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh04949");

  script_name(english:"Cisco IOS XE DHCP AAA Clients DoS (CSCuh04949)");
  script_summary(english:"Checks IOS XE version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
affected by a denial of service vulnerability.

A denial of service flaw exists in the DHCP function when handling AAA
client IP address assignment. An authenticated attacker, with a
specially crafted AAA packet, could cause the device to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31860");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31860
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e08811a4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuh04949.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

if (version == '3.7.0S') flag++;
if (version == '3.7.1S') flag++;
if (version == '3.7.2S') flag++;
if (version == '3.7.3S') flag++;
if (version == '3.8.0S') flag++;
if (version == '3.8.1S') flag++;
if (version == '3.8.2S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"aaa", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco Bug ID      : CSCuh04949' +
    '\n  Installed release : ' + version;
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
