#TRUSTED 7d7e809cb3b429fb2717a1a1100a60ad6fa5588d40e874cd67c9843de9531e5268e8ee0f48765dae42a9ee8c0c6ed8d7aade26850ee4d5d3ffedc20378c84f34483041e29b9ccf1b8789f8e12ecfaa3731a83c852720fd610a238ff0d542004c1612f561d97862d04cab91eb0f91edec198c5b60dab4ac86f6934eeb74aa3917094327fae921bdd9ab0d4d8040240feb06debb580e24fbb09d7000c3938ec64bf353051ce6f1bcebc8accdc874f71728fa31cae7b0597a5c47e7e5a75132e57e5605539a20d052a12572ce864ed80a00c52836bf48beebb35f4a6a12d2c96bc2358915f81a0ade9e68a1a588ee79285fde08af5e46ebda76a1b7c4c2a5246b056f886003c4653bd1eeeda005078bb94bd9d9430f7fb6cce371002d1ff14e7ab969346bb3784fa24638cf38075287a70e420e69f51348741fda758a1373f7ca3207aa16c59c8a2cc3fef6247bccae26668822cac0881d8ee7034a28da4e6261b95b28b2bc1823ddfb74ce9576877c2e23a8c510c23b9deaed51d365b99a335bc52422f2e26bd45d6eb8b00bf0339d4bee3ef893b4566cc1b4c75399dc957e520394e045ef5c1fb6bca9e9abac134ec0c93ba3067af4068221a7915531986520305b9c7aab3aa0406cfd86ca0ee4f3401b5e09d0cb756778bdc574d4d8c69dcc9a44a3caecb7b81bc7fda54bdba8d06f5e85c3363629cd36149df9fa9efd816dfa
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20131106-sip.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(73269);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-2107");
  script_bugtraq_id(66468);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug84789");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-RSP72010GE");

  script_name(english:"Cisco 7600 Series Route Switch Processor 720 with 10 Gigabit Ethernet Uplinks Denial of Service (cisco-sa-20140326-RSP72010GE)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in Cisco 7600 Series Route Switch Processor
720 with 10 Gigabit Ethernet Uplinks that could allow a remote,
unauthenticated attacker to cause the route processor to reboot or
stop forwarding traffic, resulting in a denial of service condition.

This vulnerability affects models RSP720-3C-10GE and RSP720-3CXL-10GE
that have onboard Kailash FPGA versions prior to 2.6 and are running
an affected version of Cisco IOS Software.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-RSP72010GE
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bc99620");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-RSP72010GE.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/31");

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

flag = 0;
override = 0;
cbi = "CSCug84789";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if (ver == '12.2SRC') flag++;
if (ver == '12.2(33)SRC') flag++;
if (ver == '12.2(33)SRC1') flag++;
if (ver == '12.2(33)SRC2') flag++;
if (ver == '12.2(33)SRC3') flag++;
if (ver == '12.2(33)SRC4') flag++;
if (ver == '12.2(33)SRC5') flag++;
if (ver == '12.2(33)SRC6') flag++;
if (ver == '12.2SRD') flag++;
if (ver == '12.2(33)SRD') flag++;
if (ver == '12.2(33)SRD1') flag++;
if (ver == '12.2(33)SRD2') flag++;
if (ver == '12.2(33)SRD2a') flag++;
if (ver == '12.2(33)SRD3') flag++;
if (ver == '12.2(33)SRD4') flag++;
if (ver == '12.2(33)SRD4a') flag++;
if (ver == '12.2(33)SRD5') flag++;
if (ver == '12.2(33)SRD6') flag++;
if (ver == '12.2(33)SRD7') flag++;
if (ver == '12.2(33)SRD8') flag++;
if (ver == '12.2SRE') flag++;
if (ver == '12.2(33)SRE') flag++;
if (ver == '12.2(33)SRE0a') flag++;
if (ver == '12.2(33)SRE1') flag++;
if (ver == '12.2(33)SRE2') flag++;
if (ver == '12.2(33)SRE3') flag++;
if (ver == '12.2(33)SRE4') flag++;
if (ver == '12.2(33)SRE5') flag++;
if (ver == '12.2(33)SRE6') flag++;
if (ver == '12.2(33)SRE7') flag++;
if (ver == '12.2(33)SRE7a') flag++;
if (ver == '12.2(33)SRE8') flag++;
if (ver == '12.2(33)SRE9') flag++;
if (ver == '12.2(33)SRE9a') flag++;
if (ver == '12.2ZI') flag++;
if (ver == '12.2(33)ZI') flag++;
if (ver == '12.2ZZ') flag++;
if (ver == '12.2(33)ZZ') flag++;
if (ver == '15.0S') flag++;
if (ver == '15.0(1)S') flag++;
if (ver == '15.0(1)S1') flag++;
if (ver == '15.0(1)S2') flag++;
if (ver == '15.0(1)S3a') flag++;
if (ver == '15.0(1)S4') flag++;
if (ver == '15.0(1)S4a') flag++;
if (ver == '15.0(1)S5') flag++;
if (ver == '15.0(1)S6') flag++;
if (ver == '15.1S') flag++;
if (ver == '15.1(1)S') flag++;
if (ver == '15.1(1)S1') flag++;
if (ver == '15.1(1)S2') flag++;
if (ver == '15.1(2)S') flag++;
if (ver == '15.1(2)S1') flag++;
if (ver == '15.1(2)S2') flag++;
if (ver == '15.1(3)S') flag++;
if (ver == '15.1(3)S0a') flag++;
if (ver == '15.1(3)S1') flag++;
if (ver == '15.1(3)S2') flag++;
if (ver == '15.1(3)S3') flag++;
if (ver == '15.1(3)S4') flag++;
if (ver == '15.1(3)S6') flag++;
if (ver == '15.2S') flag++;
if (ver == '15.2(1)S') flag++;
if (ver == '15.2(1)S1') flag++;
if (ver == '15.2(1)S2') flag++;
if (ver == '15.2(2)S') flag++;
if (ver == '15.2(2)S1') flag++;
if (ver == '15.2(2)S2') flag++;
if (ver == '15.2(4)S') flag++;
if (ver == '15.2(4)S1') flag++;
if (ver == '15.2(4)S3a') flag++;
if (ver == '15.2(4)S4') flag++;
if (ver == '15.2(4)S4a') flag++;
if (ver == '15.3S') flag++;
if (ver == '15.3(1)S') flag++;
if (ver == '15.3(1)S2') flag++;
if (ver == '15.3(2)S') flag++;
if (ver == '15.3(2)S0a') flag++;
if (ver == '15.3(2)S1') flag++;
if (ver == '15.3(2)S2') flag++;
if (ver == '15.3(3)S') flag++;
if (ver == '15.3(3)S1') flag++;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
  if (check_cisco_result(buf))
  {
    pattern = "(\d+)\s+\d+\s+Route Switch Processor 720.*?(RSP720-3CXL-10GE|RSP720-3C-10GE)";
    match = eregmatch(string:buf, pattern:pattern);
    if (!isnull(match))
    {
      temp_flag = 1;
      slot = match[1];
    }
  }
  else if (cisco_needs_enable(buf)) override = 1;

  if (temp_flag)
  {
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_asic-version_slot_" + slot,
      "show asic-version slot " + slot);
    if (check_cisco_result(buf))
    {
      pattern = "KAILASH\s+\d+\s+\(((?:\d+\.)*\d+)\)";
      match = eregmatch(string:buf, pattern:pattern);
      if (!isnull(match) && ver_compare(ver:match[1], fix:"2.6", strict:FALSE) == -1) flag = 1;
    }
    else if (cisco_needs_enable(buf)) override = 1;
  }

  if (override) flag = 1;
}

if (flag)
{
  report =
    '\n  Cisco Bug ID      : ' + cbi +
    '\n  Installed release : ' + ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
