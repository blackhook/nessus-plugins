#TRUSTED 8f938ff6c4f53c4a583062d37100ac9dda0c9d1a5e42e54117d7f6be96cf32d2b5eb784d64e7dca4ea1c63646102835b364736ce5d693c3d0980de033abce1675774ea4ef2b1ced0532d4cf20027f890394ce88655224fd559228daae69a472c52bd925cfe8ce443e0a900e5d40f1e614625d3c04db61cea1646124d77f19a454401d3a4f98211feeea2168d62a68d84e71e69e1d9fa6e4db40c759155338f1a6b92a613be1c6806cc0053302cabb16fafebcb906d6d8089174a6d8f636a9f8a61b82393d3856d654540da7886c70318ea9c6ed1f6b2e30fbbf80084ed318e2e12b7a57ea7878572999aadf73a6e46311cf066dab8ed38ffb659d103edec664b8f9d8c07b6d45ffb01394c34c12e577eb30e2733dd265c875829aa4bcf950c742e5a0ea452bc354d71b6e9aaad11ea913d34aa2978c2be037cca6507948f8dd42a25c75745929a6e7e1eb76728068819202b491ba6a6dee5b2fe4ce9bb2ea4846056d800bea1cba2598146bd3acbba50271635a924b0ded5613280319a04a8bce6e49cff874d27286374e2997be2f20c7960a649c8fda73ba1196e9b6f64b4a39305202ef4ec63ac2281070edd384988c2218309dde2851efdf6d0f0c621912d932495f0ed2b79994feda20fff790c98e0d3e7e360bb968174ab254303759c6640856aecc2cb03c566f3df6221cfe943f46dd72b19f5aea6cc710e64061b2821
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99033);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3859");
  script_bugtraq_id(97008);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy56385");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-ztp");

  script_name(english:"Cisco IOS XE for Cisco ASR 920 Series Routers Zero Touch Provisioning DoS (cisco-sa-20170322-ztp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote Cisco ASR 920 Series device is affected by a
denial of service vulnerability due to a format string flaw when
processing DHCP packets for Zero Touch Provisioning. An
unauthenticated, remote attacker can exploit this issue, via a
specially crafted DHCP packet, to cause the device to reload.

Note that for this vulnerability to be exploited, the device must be
configured to listen on the DHCP server port. By default, the device
does not listen on this port.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-ztp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?339c4225");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy56385");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy56385");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if (model !~ "^ASR920$")
  audit(AUDIT_HOST_NOT, "an affected model");

flag = 0;
override = 0;

if (
  ver == "3.13.4S" ||
  ver == "3.13.5S" ||
  ver == "3.13.5aS" ||
  ver == "3.13.6S" ||
  ver == "3.13.6aS" ||
  ver == "3.14.3S" ||
  ver == "3.14.4S" ||
  ver == "3.15.2S" ||
  ver == "3.15.3S" ||
  ver == "3.15.4S" ||
  ver == "3.16.0S" ||
  ver == "3.16.1S" ||
  ver == "3.16.1aS" ||
  ver == "3.16.2S" ||
  ver == "3.16.2aS" ||
  ver == "3.16.0cS" ||
  ver == "3.16.3S" ||
  ver == "3.16.2bS" ||
  ver == "3.16.3aS" ||
  ver == "3.17.0S" ||
  ver == "3.17.1S" ||
  ver == "3.17.2S " ||
  ver == "3.17.1aS" ||
  ver == "3.18.0aS" ||
  ver == "3.18.0S" ||
  ver == "3.18.1S" ||
  ver == "3.18.2S" ||
  ver == "3.18.3vS" ||
  ver == "3.18.0SP" ||
  ver == "3.18.1SP" ||
  ver == "3.18.1aSP" ||
  ver == "3.18.1bSP" ||
  ver == "3.18.1cSP"
)
{
  flag++;
}

cmds = make_list();
# Confirm whether a device is listening on the DHCP server port
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  pat = "^(Proto|\d+)?.*17(\(v6\))?\s+(--listen--|\d+.\d+.\d+.\d+).*\s67\s";

  buf = cisco_command_kb_item("Host/Cisco/Config/show ip sockets", "show ip sockets");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:pat, string:buf))
    {
      cmds = make_list(cmds, "show ip sockets");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCuy56385",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
