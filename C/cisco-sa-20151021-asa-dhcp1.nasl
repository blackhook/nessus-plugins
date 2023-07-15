#TRUSTED 6595fea9673d3ff17e160e25fea5fa93a61d2c96a37b6aeb02510217f4c20061d6a69d77af13c170a57cf09d8f89006a7b56f7d69260b73559767bf75ab47d5c419c2f56b22e2fc10aca1219ee8a05deb979e81dfc056286e2c8328c62ea8a80ca79f86786c1133c784779c59b7f597b8933b3d0c4a95ea4e0ba431c5c828592d2a0752dfe944c034dd9a3d0780d607d51b76df20668e43a28ff947e949b63ead83735860fefd472db9eba69a01c265a730e10b5f2501cef5cbe24e7992f25f00074529629be92ee911c5f2837f8696b9c16ff5ec66adde47ea552ff3773d8b22d4c3ad3a6152d3227f0c218e4f70adc912de1e81d1cbf1c61ad1be990a63b03484f969df669740ea785b52cf1942421ca29ef7a4da804d8fa3abc619e44d189a0b6c45c07065a7828190cd4f70fa78a6f7d2a2f54096a25d4d515b173f919f1589856dd61defd4038c55213c48df4099b9e97505bce7414078bd6c21c7f078915f8b3e01c00dce1a2f984fc3ac03838a2a139b807733e7ff936a84883607c90309b31586ea4a462b644fce5be86ec73c83ce2653c0e25d3b8b2b056cfdbc3c20dd4760f623cb653886f7ba1692b694d4c38741981dc569315ba726879b15ba5b145f0934792a0bb21d7c1b5ea965a85f700fda02d90d3b335791524ccfebe9ebfa13c4a06a52fbcbd0197d7b3c6070ff9504c2990e18d07709d542c7870b1c9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93528);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2015-6324");
  script_bugtraq_id(77257);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus56252");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus57142");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151021-asa-dhcp1");

  script_name(english:"Cisco ASA DHCPv6 Relay DoS (cisco-sa-20151021-asa-dhcp1)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the remote Cisco Adaptive
Security Appliance (ASA) device is affected by a denial of service
vulnerability in the DHCPv6 relay feature due to improper validation
of DHCPv6 packets. An unauthenticated, remote attacker can exploit 
this, via specially crafted DHCPv6 packets, to cause the device to
reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151021-asa-dhcp1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cad6d0f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCus56252");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCus57142");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug IDs CSCus56252 and
CSCus57142. Alternatively, disable the DHCPv6 relay feature.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

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
# Cisco ASA 5500 Series Adaptive Security Appliances
# Cisco ASA 5500-X Series Next-Generation Firewalls
# Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches and
# Cisco 7600 Series Routers
# Cisco ASA 1000V Cloud Firewall
# Cisco Adaptive Security Virtual Appliance (ASAv)

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V' &&
  model != 'v'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500 5500-X 6500 7600 1000V or ASAv");

fixed_ver = NULL;

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.37)"))
  fixed_ver = "9.0(4.37)";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.6)"))
  fixed_ver = "9.1(6.6)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4)"))
  fixed_ver = "9.2(4)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3.6)"))
  fixed_ver = "9.3(3.6)";

else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(2)"))
  fixed_ver = "9.4(2)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if DHCP6 relay is in play
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-ipv6-dhcprelay", "show running-config ipv6 dhcprelay");
  if (check_cisco_result(buf))
  {
    if ("ipv6 dhcprelay enable outside" >< buf) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCP6 relaying is not enabled");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : CSCus56252 and CSCus57142' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
