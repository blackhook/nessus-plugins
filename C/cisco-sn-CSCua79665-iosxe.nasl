#TRUSTED 19ba7522590b6e32340c70cf235530c19908029afce83f1cbb16bf60e213e4b5f410ebaf7c349799b95b3fdcad6690c9daf0586b587120a9c683717fa272d4e81f182365249155f0f12a2180033f78431c79637469ead3187a6e8b56b87cca008b67c604b6bf9b8dd8a57595c6393a2e8003c9a3bc11cd07510fe91450f73effaff2ecdfc6358ba4b7d5667556ba1a809c9445efc0382b1f0dfab71a14bc6e67a6c1c1093e6b095d2fe72a6b2ca0d4ae94e9cb00e04eb1f2af9878561ebe736f1844c3081df170798d8797ab87195bff7c904059bd8a07197036a3b8bcc969de23f7784beeb40e2e05a781131205376d2b5ecbcf7e9dfdeeb3d4b35cdd037cebcdac3c1ce49aad281458e88af470f36d7333b3b8eca86ffb00222f4b14257e63080193e9943de6993654910d184abfa4b75661b14ef3dfb592c589782a2ef9ee931388b3c04a7ad3148394733b19adf9c0b022c77fe39a6aaeed514633f8ba6be9ec8802de1e0831e563a0717cc15812b3b58aba4f395b47d3c3a1640fd93a10ccea69152723718d8e873ccb9565bd26b3be6fe779e368499a338f4c265adac6eabbfc41d83a14f94f0e55790e1d7cbbaadfd47c873b937481fba21e8f92e631d06aec3bee4a8e4183cd196d8669bd2357d25c40d343cf31bc5d8c5844208319c10a9cb99300814571517abed7f0b50722856de70095f17e61c82b5c2ce50577
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82586);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0639");
  script_bugtraq_id(73337);
  script_xref(name:"CISCO-BUG-ID", value:"CSCua79665");

  script_name(english:"Cisco IOS XE Common Flow Table DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability in the Common Flow Table (CFT)
feature due to improper processing of IPv6 packets encapsulated inside
IPv4 UDP packets. An unauthenticated, remote attacker, using malformed
packets, can exploit this to cause a device reload.

Note this only affects devices that have configured Media Monitoring
(MMON) or Network-Based Application Recognition (NBAR).");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cbb5bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCua79665");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

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

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Bug and CVRF
if (version == "3.7.0S") flag++;
if (version == "3.8.0S") flag++;

# CVRF
if (version == "3.6.0S") flag++;
if (version == "3.6.1S") flag++;
if (version == "3.6.2S") flag++;
if (version == "3.7.1S") flag++;
if (version == "3.7.2S") flag++;
if (version == "3.7.3S") flag++;
if (version == "3.7.4S") flag++;
if (version == "3.7.5S") flag++;

# Check configs
if (flag > 0)
{
  flag = 0;

  # Check NBAR
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^\s+ip nbar classification tunneled-traffic (ipv6inip|teredo)", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

  # Check MMON
  buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map-type-perf-mon", "show policy-map type performance-monitor");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^Service-policy performance-monitor (input|output): mmon_policy", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCua79665' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
