#TRUSTED a802d357e85168441b0cb7d7048806ba0e262f908465e2ea7b5c0005437bc9ac2b70256952b2a643613295f627efdd41e2fc7f036e53d2b65861ab79a83a1639c27fc7083237b4dfddb1da4f3ea0aa4ac2429062edec64e505ca45d268ccb91a8c0bedcefc76b7e55b507eef142ea7a5a6d79d7033d7fd1f8dfe0cc92614882f02564d92da63469eaa9aab8ddd707c12710c590b0477f43a3de1ad421389b39995a32e5502f3274333fd7b6ccdb3fa4068a549151cf79b7510ab464ed32fbd4e1424440b0355dfbf3c5b62c734a929018e9029dbcbdee8975d5e687b84cd9e0c47c501961665c347d29297396b97f8454f2f34ded4b2485ffcdb5c1bb46bddded6208438252708d67b73dd1fadb311ac48971d149fc448364706273c556b5397cd7a13143ccecaa1259f604008daec0ed042c0d2e3fd14e6549d2d89ce32b91c17192faea9f12c88c8f1f520bc3622bcd5b9f16deb03f01e570c9c56984ff86259d6d333e9731d66e205d728f64db945d7dcc6e5c0e720b9586da38f6999450cef6784da02cc9190db648f135904408ae47ed6b5e73a7c05ecd2a2df98a8b6c22339a206d394f5fa3c2b5c055f435097f5c0205644b85a85923004f278f1bb3f20e5ab8bc4622bb127b2eb35c4895e22468ce194677126d4944c36d4413557d80419de9c966216879d020b07a295bd5d20f74aa8649e7c6ed47695f67e0c3091
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93530);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2015-6326");
  script_bugtraq_id(77261);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu07799");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151021-asa-dns2");

  script_name(english:"Cisco ASA DNS Packet Handling DoS (cisco-sa-20151021-asa-dns2)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the remote Cisco Adaptive
Security Appliance (ASA) device is affected by a denial of service
vulnerability due to improper processing of DNS packets. An
unauthenticated, remote attacker can exploit this, via a spoofed reply
packet with a crafted DNS response, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151021-asa-dns2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1387798a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu07799");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCuu07799.
Alternatively, remove DNS name-server values configured for any DNS
server groups.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6326");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

# Affected :
# Cisco ASA 1000V Cloud Firewall
# Cisco ASA 5500 Series Adaptive Security Appliances
# Cisco ASA 5500-X Series Next-Generation Firewalls
# Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches
# and Cisco 7600 Series Routers
# Cisco Adaptive Security Virtual Appliance (ASAv)
# Cisco FirePOWER 9300 ASA Security Module

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^93[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V' &&
  model != 'v'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500 5500-X 6500 7600 1000V 9300 or ASAv");

fixed_ver = NULL;

if (ver =~ "^7\.2[^0-9]")
  fixed_ver = "8.2(5.58)";

else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.58)"))
  fixed_ver = "8.2(5.58)";

else if (ver =~ "^8\.3[^0-9]")
  fixed_ver = "8.4(7.29)";

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.29)"))
  fixed_ver = "8.4(7.29)";

else if (ver =~ "^8\.5[^0-9]")
  fixed_ver = "9.0(4.37)";

else if (ver =~ "^8\.6[^0-9]")
  fixed_ver = "9.0(4.37)";

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.17)"))
  fixed_ver = "8.7(1.17)";

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.37)"))
  fixed_ver = "9.0(4.37)";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.6)"))
  fixed_ver = "9.1(6.6)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4)"))
  fixed_ver = "9.2(4)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3.6)"))
  fixed_ver = "9.3(3.6)";

else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(1.5)"))
  fixed_ver = "9.4(1.5)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if at least one DNS server IP address is configured
# under a DNS server group
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config dns server-group", "show running-config dns server-group");

  if (check_cisco_result(buf))
  {
    if (
      ("DNS server-group" >< buf) &&
      (preg(multiline:TRUE, pattern:"name-server [0-9\.]+", string:buf))
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because a DNS server IP address is not configured under a DNS server group");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCuu07799' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
