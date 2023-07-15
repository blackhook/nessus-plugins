#TRUSTED 0e1c50147d9c42e212471601d8cdf640425412db8a22128541e5cba60aaf0e9146360934b7bc1997c3a3764e6500f1765cd0ad0e3668d7f27ea8c28754cc4cda61ea96ddff1d4d083c332f693400e2884d40614cead5964a8064934e6b53396088cbff4b52e0cc8abf484f2932c0526941f9eb692ac0925b24fb10490a0e616ffa32a6b2ade10d5a2ef15edf407022b67f72e9c84081bb2c7f6fe5213ac0ea7ff7855a40749879c9f2896447872c6cdfbae9a6cafa816161bc60ba221d2974330f5a9d190881cc0badc9cec64c76f9695ce78f1f0e0fa08b037617234cf216f5f1a430ec9c16ac5e93641f7844a169e807162a19d752192921cfad748ae3756929bc413aab249b4c1519b93f402eacc44814e1ced91a02c9e80dbebe1c455607d1c1cf189f698dba11bdad660cc97cd8b686984ca7a7b623eace33b9c2e0f2b3e2dda8c5fa0ecb8b176e8253de208aa86bd4f4bc00faded631729b7f4a546c9ca99b70ddfb7a364cb040af199047dcfd0933265355815647ab6723fbef067aa6f2b1ccf906de05b8d60eb571b1ad58bebd63a7ff533c6fe3893b15a4007502f6ae447d0cbc4facf88f5440132c741e01b9ea24f3176f8c83ac2cd59497e7cdd24b1257b1da8a183cd6baa7692d043a35201fb349748a622d71d2c8a5b48c9db7bb381af37213e1cf4f503d46920994528a06b1188bcfbb922ee441f84ce36080
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69138);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id("CVE-2013-3414");
  script_bugtraq_id(61451);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug83080");

  script_name(english:"Cisco ASA WebVPN XSS");
  script_summary(english:"Checks ASA version");

  script_set_attribute(attribute:"synopsis", value:
"The remote security device is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco ASA is missing
a security patch and is affected by a cross-site scripting vulnerability
in the WebVPN portal login page.  An attacker could exploit this by
tricking a user into requesting a specially crafted URL, resulting in
arbitrary script code execution.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=30214
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc0e96e5");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=30214");
  script_set_attribute(attribute:"solution", value:
"According to the Cisco Security Notice for CVE-2013-3414, fixes can be
obtained by contacting normal support channels.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");
include("audit.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
ver = extract_asa_version(asa);
if (isnull(ver))
  audit(AUDIT_FN_FAIL, 'extract_asa_version');

else if (ver == '7.0(1)')
  vuln = TRUE;
else if (ver == '7.0(1)4')
  vuln = TRUE;
else if (ver == '7.0(2)')
  vuln = TRUE;
else if (ver == '7.0(3)')
  vuln = TRUE;
else if (ver == '7.0(4)')
  vuln = TRUE;
else if (ver == '7.0(4)2')
  vuln = TRUE;
else if (ver == '7.0(5)')
  vuln = TRUE;
else if (ver == '7.0(5)12')
  vuln = TRUE;
else if (ver == '7.0(6)')
  vuln = TRUE;
else if (ver == '7.0(6)18')
  vuln = TRUE;
else if (ver == '7.0(6)22')
  vuln = TRUE;
else if (ver == '7.0(6)26')
  vuln = TRUE;
else if (ver == '7.0(6)29')
  vuln = TRUE;
else if (ver == '7.0(6)32')
  vuln = TRUE;
else if (ver == '7.0(6)4')
  vuln = TRUE;
else if (ver == '7.0(6)8')
  vuln = TRUE;
else if (ver == '7.0(7)')
  vuln = TRUE;
else if (ver == '7.0(7)1')
  vuln = TRUE;
else if (ver == '7.0(7)12')
  vuln = TRUE;
else if (ver == '7.0(7)4')
  vuln = TRUE;
else if (ver == '7.0(7)9')
  vuln = TRUE;
else if (ver == '7.0(8)')
  vuln = TRUE;
else if (ver == '7.0(8)12')
  vuln = TRUE;
else if (ver == '7.0(8)13')
  vuln = TRUE;
else if (ver == '7.0(8)2')
  vuln = TRUE;
else if (ver == '7.0(8)8')
  vuln = TRUE;
else if (ver == '7.1(2)')
  vuln = TRUE;
else if (ver == '7.1(2)16')
  vuln = TRUE;
else if (ver == '7.1(2)20')
  vuln = TRUE;
else if (ver == '7.1(2)24')
  vuln = TRUE;
else if (ver == '7.1(2)28')
  vuln = TRUE;
else if (ver == '7.1(2)38')
  vuln = TRUE;
else if (ver == '7.1(2)42')
  vuln = TRUE;
else if (ver == '7.1(2)46')
  vuln = TRUE;
else if (ver == '7.1(2)49')
  vuln = TRUE;
else if (ver == '7.1(2)53')
  vuln = TRUE;
else if (ver == '7.1(2)61')
  vuln = TRUE;
else if (ver == '7.1(2)64')
  vuln = TRUE;
else if (ver == '7.1(2)72')
  vuln = TRUE;
else if (ver == '7.1(2)81 ')
  vuln = TRUE;
else if (ver == '7.2(1)')
  vuln = TRUE;
else if (ver == '7.2(1)13')
  vuln = TRUE;
else if (ver == '7.2(1)19')
  vuln = TRUE;
else if (ver == '7.2(1)24')
  vuln = TRUE;
else if (ver == '7.2(1)9')
  vuln = TRUE;
else if (ver == '7.2(2)')
  vuln = TRUE;
else if (ver == '7.2(2)10')
  vuln = TRUE;
else if (ver == '7.2(2)14')
  vuln = TRUE;
else if (ver == '7.2(2)18')
  vuln = TRUE;
else if (ver == '7.2(2)19')
  vuln = TRUE;
else if (ver == '7.2(2)22')
  vuln = TRUE;
else if (ver == '7.2(2)34')
  vuln = TRUE;
else if (ver == '7.2(2)6')
  vuln = TRUE;
else if (ver == '7.2(3)')
  vuln = TRUE;
else if (ver == '7.2(3)1')
  vuln = TRUE;
else if (ver == '7.2(3)12')
  vuln = TRUE;
else if (ver == '7.2(3)16')
  vuln = TRUE;
else if (ver == '7.2(4)')
  vuln = TRUE;
else if (ver == '7.2(4)18')
  vuln = TRUE;
else if (ver == '7.2(4)25')
  vuln = TRUE;
else if (ver == '7.2(4)27')
  vuln = TRUE;
else if (ver == '7.2(4)30')
  vuln = TRUE;
else if (ver == '7.2(4)33')
  vuln = TRUE;
else if (ver == '7.2(4)6')
  vuln = TRUE;
else if (ver == '7.2(4)9')
  vuln = TRUE;
else if (ver == '7.2(5)')
  vuln = TRUE;
else if (ver == '7.2(5)10')
  vuln = TRUE;
else if (ver == '7.2(5)2')
  vuln = TRUE;
else if (ver == '7.2(5)4')
  vuln = TRUE;
else if (ver == '7.2(5)7')
  vuln = TRUE;
else if (ver == '7.2(5)8 ')
  vuln = TRUE;
else if (ver == '8.0(1)2')
  vuln = TRUE;
else if (ver == '8.0(2)')
  vuln = TRUE;
else if (ver == '8.0(2)11')
  vuln = TRUE;
else if (ver == '8.0(2)15')
  vuln = TRUE;
else if (ver == '8.0(3)')
  vuln = TRUE;
else if (ver == '8.0(3)12')
  vuln = TRUE;
else if (ver == '8.0(3)19')
  vuln = TRUE;
else if (ver == '8.0(3)6')
  vuln = TRUE;
else if (ver == '8.0(4)')
  vuln = TRUE;
else if (ver == '8.0(4)16')
  vuln = TRUE;
else if (ver == '8.0(4)23')
  vuln = TRUE;
else if (ver == '8.0(4)25')
  vuln = TRUE;
else if (ver == '8.0(4)28')
  vuln = TRUE;
else if (ver == '8.0(4)3')
  vuln = TRUE;
else if (ver == '8.0(4)31')
  vuln = TRUE;
else if (ver == '8.0(4)32')
  vuln = TRUE;
else if (ver == '8.0(4)33')
  vuln = TRUE;
else if (ver == '8.0(4)9')
  vuln = TRUE;
else if (ver == '8.0(5)')
  vuln = TRUE;
else if (ver == '8.0(5)20')
  vuln = TRUE;
else if (ver == '8.0(5)23')
  vuln = TRUE;
else if (ver == '8.0(5)25')
  vuln = TRUE;
else if (ver == '8.0(5)27')
  vuln = TRUE;
else if (ver == '8.0(5)28')
  vuln = TRUE;
else if (ver == '8.0(5)31 ')
  vuln = TRUE;
else if (ver == '8.1(1)')
  vuln = TRUE;
else if (ver == '8.1(1)6')
  vuln = TRUE;
else if (ver == '8.1(2)')
  vuln = TRUE;
else if (ver == '8.1(2)13')
  vuln = TRUE;
else if (ver == '8.1(2)15')
  vuln = TRUE;
else if (ver == '8.1(2)16')
  vuln = TRUE;
else if (ver == '8.1(2)19')
  vuln = TRUE;
else if (ver == '8.1(2)23')
  vuln = TRUE;
else if (ver == '8.1(2)24')
  vuln = TRUE;
else if (ver == '8.1(2)49')
  vuln = TRUE;
else if (ver == '8.1(2)50')
  vuln = TRUE;
else if (ver == '8.1(2)55')
  vuln = TRUE;
else if (ver == '8.1(2)56')
  vuln = TRUE;
else if (ver == '8.2(0)45')
  vuln = TRUE;
else if (ver == '8.2(1)')
  vuln = TRUE;
else if (ver == '8.2(1)11')
  vuln = TRUE;
else if (ver == '8.2(2)')
  vuln = TRUE;
else if (ver == '8.2(2)10')
  vuln = TRUE;
else if (ver == '8.2(2)12')
  vuln = TRUE;
else if (ver == '8.2(2)16')
  vuln = TRUE;
else if (ver == '8.2(2)17')
  vuln = TRUE;
else if (ver == '8.2(2)9')
  vuln = TRUE;
else if (ver == '8.2(3)')
  vuln = TRUE;
else if (ver == '8.2(4)')
  vuln = TRUE;
else if (ver == '8.2(4)1')
  vuln = TRUE;
else if (ver == '8.2(4)4')
  vuln = TRUE;
else if (ver == '8.2(5)')
  vuln = TRUE;
else if (ver == '8.2(5)13')
  vuln = TRUE;
else if (ver == '8.2(5)22')
  vuln = TRUE;
else if (ver == '8.2(5)26')
  vuln = TRUE;
else if (ver == '8.2(5)33')
  vuln = TRUE;
else if (ver == '8.2(5)40')
  vuln = TRUE;
else if (ver == '8.2(5)41 ')
  vuln = TRUE;
else if (ver == '8.3(1)')
  vuln = TRUE;
else if (ver == '8.3(1)4')
  vuln = TRUE;
else if (ver == '8.3(1)6')
  vuln = TRUE;
else if (ver == '8.3(2)')
  vuln = TRUE;
else if (ver == '8.3(2)13')
  vuln = TRUE;
else if (ver == '8.3(2)23')
  vuln = TRUE;
else if (ver == '8.3(2)25')
  vuln = TRUE;
else if (ver == '8.3(2)31')
  vuln = TRUE;
else if (ver == '8.3(2)33')
  vuln = TRUE;
else if (ver == '8.3(2)34')
  vuln = TRUE;
else if (ver == '8.3(2)37')
  vuln = TRUE;
else if (ver == '8.3(2)4')
  vuln = TRUE;
else if (ver == '8.4(1)')
  vuln = TRUE;
else if (ver == '8.4(1)11')
  vuln = TRUE;
else if (ver == '8.4(1)3')
  vuln = TRUE;
else if (ver == '8.4(2)')
  vuln = TRUE;
else if (ver == '8.4(2)1')
  vuln = TRUE;
else if (ver == '8.4(2)8')
  vuln = TRUE;
else if (ver == '8.4(3)')
  vuln = TRUE;
else if (ver == '8.4(3)8')
  vuln = TRUE;
else if (ver == '8.4(3)9')
  vuln = TRUE;
else if (ver == '8.4(4)')
  vuln = TRUE;
else if (ver == '8.4(4)1')
  vuln = TRUE;
else if (ver == '8.4(4)3')
  vuln = TRUE;
else if (ver == '8.4(4)5')
  vuln = TRUE;
else if (ver == '8.4(4)9')
  vuln = TRUE;
else if (ver == '8.4(5)')
  vuln = TRUE;
else if (ver == '8.4(5)6')
  vuln = TRUE;
else if (ver == '8.4(6)')
  vuln = TRUE;
else if (ver == '8.5(1)')
  vuln = TRUE;
else if (ver == '8.5(1)1')
  vuln = TRUE;
else if (ver == '8.5(1)14')
  vuln = TRUE;
else if (ver == '8.5(1)17')
  vuln = TRUE;
else if (ver == '8.5(1)6')
  vuln = TRUE;
else if (ver == '8.5(1)7')
  vuln = TRUE;
else if (ver == '8.6(1)')
  vuln = TRUE;
else if (ver == '8.6(1)1')
  vuln = TRUE;
else if (ver == '8.6(1)10')
  vuln = TRUE;
else if (ver == '8.6(1)2')
  vuln = TRUE;
else if (ver == '8.6(1)5')
  vuln = TRUE;
else if (ver == '8.7(1)')
  vuln = TRUE;
else if (ver == '8.7(1)1')
  vuln = TRUE;
else if (ver == '8.7(1)3')
  vuln = TRUE;
else if (ver == '8.7(1)4 ')
  vuln = TRUE;
else if (ver == '9.0(1)')
  vuln = TRUE;
else if (ver == '9.0(2)')
  vuln = TRUE;
else if (ver == '9.1(1)')
  vuln = TRUE;
else if (ver == '9.1(1)4')
  vuln = TRUE;
else if (ver == '9.1(2)')
  vuln = TRUE;
else
  vuln = FALSE;

override = FALSE;
if (get_kb_item("Host/local_checks_enabled") && vuln)
{
  vuln = FALSE;
  # Check that webvpn is enabled on at least one interface
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config webvpn", "show running-config webvpn");

  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:".*enable outside", string:buf))
    {
      # Check that the ssl-clientless option is configured
      buf2 = cisco_command_kb_item("Host/Cisco/Config/show running-config group-policy | include vpn-tunnel-protocol", "show running-config group-policy | include vpn-tunnel-protocol");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"vpn-tunnel-protocol.*ssl-clientless", string:buf2))
          vuln = TRUE;
      }
    }
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!vuln && !override) audit(AUDIT_HOST_NOT, "affected because the Clientless SSL VPN portal is not enabled");
}

if (vuln || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : ver,
    cmds     : make_list("show running-config webvpn", "show running-config group-policy | include vpn-tunnel-protocol"),
    xss      : TRUE
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);
