#TRUSTED 2a170e39c57dfc6539f8b2b92299b7e48cf00789196a9e738f64ec9b380c39e2892fb8dc26eccf586ee6dd454d687d14bc2ccb7faeabf981d2ccb1e248de1ba2aacfaf97eee8e89314835332943ee68ea70441218034d137b4378cc8b7738f4316895a1ff849bd5b4fd473a62a769c5e08cd74d38cf948ff773405d86e3190245b9aab833d7b2db716649558e6b68b5086028ca02d90834fc56abed17643ce324469b05e42ccede0027bb28aea4e48bc0e153401718deb6f940f28b54e4d3daf9ddd22fffde41b420d3303078d9dc24614eb89229ed1ae6d18361b73de655f361f2e1ff20f86c318cc4a192fb150abfb7f0c9b329ed8139e35be8f515edc625a28d36e8447f6fb8b29c77f6ef98a0356786ee83e879bdebf1450a656e639797add9833d246e5fa9770c3cda19aa2f94fa3ba6fbbf16626ba8c82493dd23b0ed58a5fc9dd1a9b03962c3b0b60fb4832fb52174a0aa19603130022040fc2ec3ae88e32f9111c7a5d271e7ee580c2c364e61d5699f62643c814dce62b3e1a6ee428bad6803a3752013c98df2bbf5eafffc1b2ac27ec486ee18747cdd0f03b8e4620a6ed9054c485a6ee4a73a8dbd60e0954f67f7a501882ffd1e6782619d23a2e520e01b82fcec67d86a08b43725b78992654155f72aef8a0246d66ea41747b804aa49b30dc7bcb5bf823da0bdfd9aca86a57ca21e53cc09180915f5da90a43a6dc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91855);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2014-2146");
  script_xref(name:"CISCO-BUG-ID", value:"CSCun96847");

  script_name(english:"Cisco IOS-XE Zone-Based Firewall Feature Security Bypass (CSCun96847)");
  script_summary(english:"Checks the IOS-XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS-XE software
running on the remote device is affected by a security bypass
vulnerability in the Zone-Based Firewall feature due to insufficient
zone checking for traffic belonging to existing sessions. An
unauthenticated, remote attacker can exploit this, by injecting
spoofed traffic that matches existing connections, to bypass security
access restrictions on the device and gain access to resources.");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCun96847");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=39129");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.
Alternatively, disable the Zone-Based Firewall feature according to
the vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2146");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

# Fix version = 3.15.0S
if (
  ver =~ "^[0-2](\.[0-9]+){0,2}[a-z]*S" ||
  ver =~ "^3\.[0-9](\.[0-9]+)?[a-z]*S" ||
  ver =~ "^3\.1[0-4](\.[0-9]+)?[a-z]*S"
) flag++; # version affected

if (flag > 0 && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  # verify zone-based firewall is enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show_zone_security", "show zone security");
  if (check_cisco_result(buf))
  {
    if (preg(pattern:"Member Interfaces:", multiline:TRUE, string:buf))
      flag = 1;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCun96847' +
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : See solution.' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
