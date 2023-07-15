#TRUSTED 0685614193b45ddec5cc88683919b2446e8d716f912528201a2d27a5173bcddf1f8e33c961bbf2c93b047e7e27d81e193a0be500eed0f8144ba37e63b7f0a00e51e0152ca21da4c671afcdbaa12454545b4cc2c2451143b593bb1036414341030e3baeade3b2d84a38eed5d59b853b26cd5d6b1e9ca208826f7f3494307f914f9a4584f7fed010296217e21efa921c1b00d96ee4f5265657207ad79b22c959b4ead423d3863cf7135c68f6072837ea7b4f8ca11749e6c156d496998f494bbc468cc09a3ecc46f6fbb4c9100e9d1ad607109677a6c66d3efb67d71c4dbfcb8349f0a6e4e1b837c532a1e51e19ff49edb51bfd7c4780bc1d7362d731ae8b8d065e069cdf8c8c5a95d03adac6a1567a920eb0690af4b82f640495d621c3bbaac3f98aa10d69460fa5ad8e30a136d6e8b11a90dad08808a0a8b2e635cd425e3efc606c3d63377941726b635a0b78402782aa7661a9522fc003b6621811b25def2cd7101421b5813a3b70a3658a85a43bc3fe36ab63a9e626417f0fae5d7b061745bac1b11c5b9426865de33f382c300cb36ec33a7423da11dde1c609707f8c5ff7a4e75cf440501577f68591ca23e6cb071af5037cf2b55cfc099aa6d5cc6868a5119542dd7cb51f6942078c8d8a0f062d3258e746a7bda9f20f77549c61d2a88bc6753fd01b13449ced3cc7db01700d614eccb9ca423f9e3ca3e88ffc9c2cf42a64
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86250);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-6280");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus73013");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-sshpk");

  script_name(english:"Cisco IOS XE SSHv2 RSA-Based User Authentication Bypass (CSCus73013)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch, and is configured for SSHv2 RSA-based user authentication. It
is, therefore, affected by a flaw in the SSHv2 protocol implementation
of the public key authentication method. An unauthenticated, remote
attacker can exploit this, via a crafted private key, to bypass
authentication mechanisms. In order to exploit this vulnerability an
attacker must know a valid username configured for RSA-based user
authentication and the public key configured for that user.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-sshpk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2660861");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus73013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
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

flag     = 0;
override = FALSE;

if (version =='3.6.0E') flag++;
if (version =='3.6.0aE') flag++;
if (version =='3.6.0bE') flag++;
if (version =='3.6.1E') flag++;
if (version =='3.6.2E') flag++;
if (version =='3.6.2aE') flag++;
if (version =='3.7.0E') flag++;
if (version =='3.10.0S') flag++;
if (version =='3.10.01S') flag++;
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
if (version =='3.13.0S') flag++;
if (version =='3.13.1S') flag++;
if (version =='3.13.2S') flag++;
if (version =='3.14.0S') flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE software", version);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-begin-ip-ssh-pubkey-chain", "show running-config | begin ip ssh pubkey-chain");
  if (check_cisco_result(buf))
  {
    if (
      "ip ssh pubkey-chain" >< buf &&
      "username" >< buf
    )
      flag = 1;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCus73013' +
    '\n  Installed release : ' + version +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
