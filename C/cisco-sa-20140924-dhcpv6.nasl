#TRUSTED 0fe6da30fd16cfa6a83ad8ada7150c352c977aebe9c8fa2adccd9605eb56df6b230498ada8e1ac67c48365d540d905a87855c9874aef4a1e22ee583636a67cbed7806b90870256117a3de03105d8788d0bacb9bcd0938e23113d2b992e0b156558d44dd4e6dc006810d21a37ac86b30748b5932f8917199c96fb79ffeb066e3d5f95535961cae6e7b5c987d8fc714ddc2328c9941303aafa6c066a2eab6dd49a1a340c20419d2ed4b4d123ff99a93469177d0c04f6082cb9b32858a266bb867143da6f93b21b456c7cc15220f46baed58478afc2d4855bbcc10b319adcda549c84652e481c69cc7b31c4dbaf034a897d715fce1d753ccc0324f299ca51031314fe25bedf61ec465aa622125aa526cb3c5630d1e25cb19a0594bb596944defb5e9a6654d76e7de20800d09e3170dc136a27fbf29c0feccd4183cb5d39389edf37bae8a7b1c7f1771d66418afb12975cdd76b59db5f490d328722c94bf81ce5a434e90e1049073342cff92d4238631246e40ea7133a0bb0ee973c70f5570106f9ddd69a48019e2d5ff4d00495ad69c6a88769a24afea7ffccdae2de1d20da23f67ea0516b9b8a4c9dee727603ba2431c79a8a6ace8b9a17e83f65057ca80a40edbc5f70366611ded327db807b808906122562e7dde7e564a844ed1ab698a64dc707eeacf00f1dac4d0a4195c574361c08ce1ee2aecf703ea3c8a0efe893a64c2be
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78029);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3359");
  script_bugtraq_id(70140);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum90081");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-dhcpv6");

  script_name(english:"Cisco IOS Software DHCPv6 DoS (cisco-sa-20140924-dhcpv6)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability in the DHCP version 6 (DHCPv6) implementation due to
improper handling of DHCPv6 packets. A remote attacker can exploit
this issue by sending specially crafted DHCPv6 packets to the
link-scoped multicast address (ff02::1:2) and the IPv6 unicast
address.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-dhcpv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?942aeed1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35609");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCum90081");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-dhcpv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

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

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

app = "Cisco IOS";
cbi = "CSCum90081";
fixed_ver = NULL;

#15.1MR
if (ver == "15.1(3)MR")
  fixed_ver = "Refer to the vendor.";
#15.1MRA
else if (ver == "15.1(3)MRA" || ver == "15.1(3)MRA1" || ver == "15.1(3)MRA2")
  fixed_ver = "15.1(3)MRA3";
#15.1S
else if (ver == "15.1(3)S" || ver == "15.1(3)S0a" || ver == "15.1(3)S1" || ver == "15.1(3)S2" || ver == "15.1(3)S3" || ver == "15.1(3)S4" || ver == "15.1(3)S5a" || ver == "15.1(3)S6")
  fixed_ver = "15.1(3)S7";
#15.2S
else if (ver == "15.2(1)S" || ver == "15.2(1)S1" || ver == "15.2(1)S2" || ver == "15.2(2)S" || ver == "15.2(2)S0a" || ver == "15.2(2)S0c" || ver == "15.2(2)S0d" || ver == "15.2(2)S1" || ver == "15.2(2)S2" || ver == "15.2(4)S" || ver == "15.2(4)S0c" || ver == "15.2(4)S1" || ver == "15.2(4)S1c" || ver == "15.2(4)S2" || ver == "15.2(4)S3" || ver == "15.2(4)S3a" || ver == "15.2(4)S4" || ver == "15.2(4)S4a" || ver == "15.2(4)S5")
  fixed_ver = "15.2(4)S2t or 15.2(4)S6";
#15.2SNG
else if (ver == "15.2(2)SNG")
  fixed_ver = "Refer to the vendor.";
#15.2SNH
else if (ver == "15.2(2)SNH" || ver == "15.2(2)SNH1")
  fixed_ver = "Refer to the vendor.";
#15.2SNI
else if (ver == "15.2(2)SNI")
  fixed_ver = "15.3(3)S4";
#15.3JA
else if (ver == "15.3(3)JA75")
  fixed_ver = "Refer to the vendor.";
#15.3M
else if (ver == "15.3(3)M" || ver == "15.3(3)M1" || ver == "15.3(3)M2" || ver == "15.3(3)M3")
  fixed_ver = "15.3(3)M4";
#15.3S
else if (ver == "15.3(1)S" || ver == "15.3(1)S1" || ver == "15.3(1)S1e" || ver == "15.3(1)S2" || ver == "15.3(2)S" || ver == "15.3(2)S0a" || ver == "15.3(2)S0xa" || ver == "15.3(2)S1" || ver == "15.3(2)S1b" || ver == "15.3(2)S1c" || ver == "15.3(2)S2" || ver == "15.3(3)S" || ver == "15.3(3)S0b" || ver == "15.3(3)S1" || ver == "15.3(3)S1a" || ver == "15.3(3)S2" || ver == "15.3(3)S2a" || ver == "15.3(3)S3")
  fixed_ver = "15.3(3)S4";
#15.4CG
else if (ver == "15.4(1)CG" || ver == "15.4(1)CG1" || ver == "15.4(2)CG")
  fixed_ver = "Refer to the vendor.";
#15.4S
else if (ver == "15.4(1)S" || ver == "15.4(1)S0a" || ver == "15.4(1)S0b" || ver == "15.4(1)S0c" || ver == "15.4(1)S0d" || ver == "15.4(1)S0e" || ver == "15.4(1)S1" || ver == "15.4(1)S2")
  fixed_ver = "15.4(1)S3 or 15.4(2)S";
#15.4T
else if (ver == "15.4(1)T" || ver == "15.4(1)T1" || ver == "15.4(2)T")
  fixed_ver = "15.4(1)T2 or 15.4(2)T1";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_dhcp_interface", "show ipv6 dhcp interface");
  if (check_cisco_result(buf))
  {
    # DHCPv6
    if (preg(multiline:TRUE, pattern:"^Using pool: DHCPv6-stateful", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCPv6 is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + 
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
