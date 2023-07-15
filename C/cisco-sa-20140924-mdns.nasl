#TRUSTED 2d3d59b9fa6646ba9ec00719715b2c26c0585dc86d4620afe023d9dda765dc1153a9de7a55f8d0195678f9828705674d3178388f44a73ad4cc518e68d458bd29ae58feb4c89893f6a0d453ab2d1ed3f25368a2f5a86c0493fac53aa48d3c5113828e2e53edb19e0d669e7d332bb998fe2ab28839f4174abf6f070d9dbbb39b07c30fa07b0788cf533e51d7740e7acb8e2b527d27f837c3c4cdc118e73f6a1698d8843af683505e9ea972dfa6af999ca1c62cbcdfa5e09f28767aa7d743ce6103ba655d8beafe9b0e72a39b48da126d16f0fd14874b4856a6368bd0df3ad5651bef7da94fd1eece5f488151cb60eddf3032708f4786df86cec2293f6d9d6a223d63def9ba362cd73cdac67ceecc1aafcc282dfeb5667ad871c6dc680df820056a04091e689d9b8e99dffcabd20462469708411cb3c95a68c9d8393a8772019aee7ec7f6aeae85209ef708afdb1212e943fa8fad7047a21face3ddcb740baf1c5a3df9f10131f5c1e75715fd670ae15904138b8d2cb912031f1e4cbe3a2b0a2d007d392b52eba68a4177b6e2b3ac42648a49eabd62afa82db6ba4c0f6dea65fbc60f3ef4ce82c94d4f6b49a7716de11709fe147e2dd5bc9a03eae8e141828169fa62a99543304fdb65de2725fe19b5d529104071f054f2083cdd6e6c729e29200d82f58367e7baa8e1976dda0020459d12571cff862a6ce49f61f31d7e780a0b19
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78031);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3357", "CVE-2014-3358");
  script_bugtraq_id(70132, 70139);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj58950");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul90866");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-mdns");

  script_name(english:"Cisco IOS Software Multiple mDNS Gateway DoS Vulnerabilities (cisco-sa-20140924-mdns)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by two unspecified denial of
service vulnerabilities in the multicast DNS (mDNS) implementation. A
remote attacker can exploit this issue by sending a specially crafted
mDNS packet to cause the device to reload.

Note that mDNS is enabled by default if the fix for bug CSCum51028 has
not been applied.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-mdns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2f51db1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35023");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35607");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35608");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuj58950");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul90866");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-mdns.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

app = "Cisco IOS";
cbi = "CSCuj58950 and CSCul90866";
fixed_ver = NULL;

#15.0EZ
if (ver == "15.0(1)EZ" || ver == "15.0(1)EZ1")
  fixed_ver = "15.0(1)EZ2 or 15.0(2)EZ";
#15.1SY
else if (ver == "15.1(2)SY" || ver == "15.1(2)SY1")
  fixed_ver = "15.1(2)SY2";
#15.1XO
else if (ver == "15.1(1)XO")
  fixed_ver = "15.1(1)XO1";
#15.2E
else if (ver == "15.2(1)E")
  fixed_ver = "15.2(1)E2 or 15.2(2)E";
else if (ver == "15.2(1)E1")
{
  fixed_ver = "15.2(1)E2 or 15.2(2)E";
  cbi       = "CSCul90866";
}
#15.4S
else if (ver == "15.4(1)S")
  fixed_ver = "15.4(1)S0a, 15.4(1)S1, or 15.4(2)S";
#15.4T
else if (ver == "15.4(1)T" || ver == "15.4(1)T1")
  fixed_ver = "15.4(1)T2 or 15.4(2)T";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

# mDNS check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^17\S+\s+\S+\s+5353\s+", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because mDNS is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
