#TRUSTED 9cce8548acd3888fd4c8924a0e666125738fb464fb9e78d79c86e45f4fff869096468a4ba1208368e2b4910f74b0c2acf3d07042e0b2291a22d176cc262049974e403b84dd0479eb67e8b70111c6824bd482c770544fa5e11f8387e8877e1bab2900cc2f058c0205c2966392a0c006d4a2fdcf4d96afd8a323780ddabca7149138ea5a60273a82ae2f2992287cdbd1a6c1c8756fe05c8b9b39aa873c5ab88db6b996dd4d75a44f8e7040ac9af44bee2bf8e095db80dcc655672bfa9d21c5d7ae61970c913391828ab2929e3cea22f9b5bcc151a38f7c6b59c5f13103d9dc4959d563a28fefa955b7b59b57a111d60dc00848b9cafcb4d2e11e111e4b27e0f5af82f08a39c5c758ba8fab802d42e410244f9b0a4664ff5bb297582ffbd66d220fe76fcef3da551b188feea36c5d59b4b50cee6b597257dbcaa7bb465c097df88933ba46f5b7294f05d7d7bd31c02398c0dd356a2d3789b14766a8e723d0eb05defcfbb06bedfd221b2d6323a474ca6231210162366c66dd0ca15ab68c6bc4c89994b95c2b0dc558ae99700eb9efcfc6cf382b89940d55e12fb5122ff87cbb4bb61cc78cdb4595676db8a68ed7114bd24f7e7463073939653b1f08f4abd88f0741557a70575e37ead3cfa14f18007388025c81afe104f677d627ce2c54e6a9497c0e6e9cf7355b4005272cb9000cd64a62fb7fb53185579a788b0bcad85691a09e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83734);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0708");
  script_bugtraq_id(74382);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur29956");

  script_name(english:"Cisco IOS XE DHCPv6 Server DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the DHCPv6 server implementation due to improper
handling of DHCPv6 packets for SOLICIT messages for Identity
Association for Non-Temporary Addresses (IA-NA) traffic. An
unauthenticated, adjacent attacker can exploit this issue to cause the
device to crash, resulting in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38543");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCur29956.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");

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

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCur29956";

if (
  ver == "3.13.0S" ||
  ver == "3.13.1S" ||
  ver == "3.14.0S"
)
  fixed_ver = "See solution.";
else
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# DHCPv6 check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_binding", "show ipv6 dhcp binding");
  if (check_cisco_result(buf))
  {
    # Output is "" if  no DHCPv6 server
    if (preg(multiline:TRUE, pattern:"^Client: ", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCPv6 server is not enabled");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
