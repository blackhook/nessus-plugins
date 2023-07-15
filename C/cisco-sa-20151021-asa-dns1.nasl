#TRUSTED 6dd6d02e730766588b73b259ffcd72d0514803ac8df3cce5c4937ab1027d9aed339c4248140eda33235dbf0f8cf4804ecc9bbe12ec38798e104a8e6bddddabcf8a01ea8baabc3ab86d7b8d201a1588080c8ba9c1b42b95655ba761eeca7748d38d8282a1cdce1c06642f28a7add1e0bdb0c976014c4c1076c44839efec35ae26ec428283702dfe8d1fce05aaacf92bec2490081d143897197295a116442f7f20b0f2d0c3f877674033c8f4dc9253dd6c58b5b4e7bb48ee15a9e88f8e51cb51007cf50cfe7dbd6d85102ce3197bcafa2baa2f629d3cff5c0dd16706727afabf909501af3e03f50adaa37c2ac22608b66bf6d6426853659c4e013f2d8a5c61f8a7c6625a748d16b324d7adc0325af65a9e91011e105d685c1dc81dc1ef1f55ad8e0aba88dd181c6fb940bd0cfa7a0b6e1775038a882ae06d0620cd41961b8c2781feda60e4db5eadc4a6ee50a5d8d990fb0d2aa3dfc7ea80008405730ff41e17484dbb3b4d98e5db4005abe7907329c3a14b2a8712390dddf93e68cf2edb0488489c5d08d8640feb4949949cd2f5527cbc4b800124c9bc0c40d332aeeb4f152bc3c829850830a630d90c4bc11da5316f4ceeb3c061792c865c16dfe4bcd0325ebdd57bd7ed86f0c74c5f7a8cd134e8284c6f642cee189320cf9e662e20319d66aae46257855e2becb5e77db7dd3462766551534a5513d51a94b4f5616b7321a1c8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93529);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2015-6325");
  script_bugtraq_id(77260);
  script_xref(name:"CISCO-BUG-ID", value:"CSCut03495");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151021-asa-dns1");

  script_name(english:"Cisco ASA DNS Packet Handling DoS (cisco-sa-20151021-asa-dns1)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the remote Cisco Adaptive
Security Appliance (ASA) device is affected by a denial of service
vulnerability due to improper processing of DNS packets. An
unauthenticated, remote attacker can exploit this, via a spoofed reply
packet with a crafted DNS response, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151021-asa-dns1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1ee734e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut03495");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCut03495.
Alternatively, remove DNS name-server values configured for any DNS
server groups.");
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
# Cisco Adaptive Security Virtual Appliance (ASAv)
# Cisco ASA 1000V Cloud Firewall
# Cisco ASA 5500 Series Adaptive Security Appliances
# Cisco ASA 5500-X Series Next-Generation Firewalls
# Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches
# and Cisco 7600 Series Routers

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V' &&
  model != 'v'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500 5500-X 6500 7600 1000V or ASAv");

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

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.4)"))
  fixed_ver = "9.1(6.4)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4)"))
  fixed_ver = "9.2(4)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3.1)"))
  fixed_ver = "9.3(3.1)";

else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(1.1)"))
  fixed_ver = "9.4(1.1)";

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
    '\n  Cisco bug ID      : CSCut03495' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
