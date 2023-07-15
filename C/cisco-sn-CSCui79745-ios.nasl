#TRUSTED 8e6d780d624364769136978fbdaa2141bdcc7721a54648bf8642f7f4b19121494c1a55a3a2217c075639fb47cb21a8dd70c73c80d8219646b074673cd49276382418b6406cb4dc958f101261b5c98ca917fb3cc304c68bc1667027dde971f859a428476ff6a3a6969d441c4c95255c7e28ee288db93c43bc282d516a18c967ffb9754f2bc76f8ef9b7dc5924a734540ef160381e8fe4355a44b56f5c5a361533107110925d1ecc141970dd3c850c591fe11c7b25b91150838c7b804701004c03159ad3cc10dd2b7f7d117f2fb9b4a062c2078f37c4ce57ddb76fc2d958ab4f13804ae47d1644742703e071022108483e04458fec0f65a81d0b5f044754e539622c1b89f7a2faa65dc1395e19f7ba68646360f6fccd4a9180561295a46ba4959e27b99f7cb8f0631541ec13f6def93c8b8ae7f34a52db3d294e03e6b0e3878b46bf298eff941d96c8ab57c89977d4b075ee7d4de3c852feb4b8f16334307ff9c503279cd6010afa97dfacf056f49a3bd1c9ff96762c45ddcd42f7aca16026478e18517fade233fdd3895292fa20952c38f7fd8ec982ce065a7acb84b2a87d6c3d75189c937a2a6e9a48f0c7939f1aa9d06097ba18424b0cdc6c67466c6ccede20825b86379cac27b4390344b6d14e4c2dc473d006ad3baae272d3564fe9fce129f6f45ae85b13e895bbabb7bc36fb156b7505fe15feeeeedab6f0d5a29431beed
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76970);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3299");
  script_bugtraq_id(68177);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui79745");

  script_name(english:"Cisco IOS IPSec Packet DoS (CSCui79745)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is running a vulnerable IOS version.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
affected by a denial of service vulnerability.

A denial of service flaw exists within IPSec packet handling. An
authenticated attacker, using a malformed IPSec packet, could cause
the device to reboot.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34704");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34704
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc94d6f1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCui79745.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/01");

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

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;
override = 0;

if (version == '15.4(0.12)T') flag++;
if (version == '15.4(1)T') flag++;
if (version == '15.4(1)T1') flag++;
if (version == '15.4(1)T2') flag++;
if (version == '15.4(1)T3') flag++;
if (version == '15.4(2)T') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"crypto ipsec", string:buf)) flag = 1;
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCui79745' +
      '\n  Installed release : ' + version + 
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
