#TRUSTED 77920382f39bd7a0bb298e370e88bf6b6d3d27f257d701a256ae61880f363ec954843f56c2576933d671487be1f21454919caabd782fe19eba8c6572ae3f4baa91562f31b1e1ac8895af2cb6fc75e46a8396f624479c53f5e1770916314bc246c88803ba8701be063543ce706169189afb3357e04dbab35702ad17ea86698484388dcbde2d6a11516b9347bacfdf9c660107ab30a02160429fcc1aba8f2fa725adb3ff7015ec6d6fdb83506e8a66c81afa6dbc67e7fc4716443f2388fa9c06bf60b97828f1a082a3fd3f9ae9334a7296b20d7c83d3b671b7471c332af65ea6072cb414beeaab6ff262b62eb90aa2a9cd982542ab2cab296db718f14f8863115f8b2d12de87f95ed02d89e537053ad864f9b767da3a1948e06ce3024b3536e1e59b5fb12f233b246c15a0a8f402cf34af3221cef222f5ba390b6cf6be407acf69ff17ccaaa2cd55159c57731866fbc7f286b615c375efc572c2c55acdd8737823f95f633ebce07db61fe6cdb46dc0cd7d9c20b1cace3cac8fe328b727139040f243d3763d28a31a373516dfd601771b7b9af52b27b3aa2036c1abe94b5ca1d95606b3d07a042b031fc20e5dbccba019c40b935933df0167cafbe1c74d035c483d42285f43138503f6fb6e13b0daa2273cbfbc108fc46f329b75145a10e930dc5f0c73ac5a5353bcd2c9a866eeeb3989f91858833e0ad2ac8904bb3e6ebef0f0a6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86247);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-6278", "CVE-2015-6279");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo04400");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus19794");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-fhs");

  script_name(english:"Cisco IOS XE IPv6 Snooping DoS (cisco-sa-20150923-fhs)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing vendor-supplied security
patches, and is configured for IPv6 snooping. It is, therefore,
affected by the following vulnerabilities :

  - A flaw exists in the IPv6 Snooping feature due to
    missing Control Plane Protection (CPPr) protection
    mechanisms. An unauthenticated, remote attacker can
    exploit this to cause a saturation of IPv6 ND packets,
    resulting in a reboot of the device. (CVE-2015-6278)

  - A flaw exists in the IPv6 Snooping feature due to
    improper validation of IPv6 ND packets that use the
    Cryptographically Generated Address (CGA) option. An
    unauthenticated, remote attacker can exploit this, via a
    malformed package, to cause a saturation of IPv6 ND
    packets, resulting in a device reboot. (CVE-2015-6279)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-fhs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c8077d4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCuo04400 and CSCus19794.

Alternatively, as a temporary workaround, disable IPv6 snooping and
SSHv2 RSA-based user authentication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag     = FALSE;
override = FALSE;

if (version =='3.2.0SE') flag++;
if (version =='3.2.1SE') flag++;
if (version =='3.2.2SE') flag++;
if (version =='3.2.3SE') flag++;
if (version =='3.3.0SE') flag++;
if (version =='3.3.0XO') flag++;
if (version =='3.3.1SE') flag++;
if (version =='3.3.1XO') flag++;
if (version =='3.3.2SE') flag++;
if (version =='3.3.2XO') flag++;
if (version =='3.3.3SE') flag++;
if (version =='3.3.4SE') flag++;
if (version =='3.3.5SE') flag++;
if (version =='3.4.0SG') flag++;
if (version =='3.4.1SG') flag++;
if (version =='3.4.2SG') flag++;
if (version =='3.4.3SG') flag++;
if (version =='3.4.4SG') flag++;
if (version =='3.4.5SG') flag++;
if (version =='3.4.6SG') flag++;
if (version =='3.5.0E') flag++;
if (version =='3.5.1E') flag++;
if (version =='3.5.2E') flag++;
if (version =='3.5.3E') flag++;
if (version =='3.6.0E') flag++;
if (version =='3.6.0aE') flag++;
if (version =='3.6.0bE') flag++;
if (version =='3.6.1E') flag++;
if (version =='3.6.2E') flag++;
if (version =='3.6.2aE') flag++;
if (version =='3.7.0E') flag++;
if (version =='3.7.1E') flag++;
if (version =='3.9.0S') flag++;
if (version =='3.9.1S') flag++;
if (version =='3.9.2S') flag++;
if (version =='3.10.01S') flag++;
if (version =='3.10.0S') flag++;
if (version =='3.10.0aS') flag++;
if (version =='3.10.1S') flag++;
if (version =='3.10.2S') flag++;
if (version =='3.10.3S') flag++;
if (version =='3.10.4S') flag++;
if (version =='3.10.5S') flag++;
if (version =='3.11.0S') flag++;
if (version =='3.11.1S') flag++;
if (version =='3.11.2S') flag++;
if (version =='3.11.3S') flag++;
if (version =='3.12.0S') flag++;
if (version =='3.12.1S') flag++;
if (version =='3.12.2S') flag++;
if (version =='3.12.3S') flag++;
if (version =='3.13.0S') flag++;
if (version =='3.13.1S') flag++;
if (version =='3.13.2S') flag++;
if (version =='3.14.0S') flag++;
if (version =='3.14.1S') flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE software", version);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;
  buf = cisco_command_kb_item("Host/Cisco/Config/show-ipv6-snooping-policies", "show ipv6 snooping policies");
  if (check_cisco_result(buf))
  {
    if ("Snooping" >< buf)
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : CSCuo04400 / CSCus19794' +
    '\n  Installed release : ' + version +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
