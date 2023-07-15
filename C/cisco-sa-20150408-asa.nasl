#TRUSTED 53ac7f9558e3a63e22f362d0fa270badb21150a500b8d90773eb72756173a5c35ba829bff754e1c7879b51cc62e1b311ce0b760addf9b50fe353c8cdb15693c16fa050c295c80850a147a8be89323e1915c8de3d736bbb458c11d5c6a3fa743775f188672dcd49c46379ac751a1b9fefc88a579cced93bec22d3317bf78f4c26d8f97b6007ab7892ae5a9903fb962ec70b585ff736b24c53fcb7233578de7270fe1d014ec14c1444bcd665dd4774fa170a20f8f378412fb16692ddb54fc5cfafe94b24fa1cd4e71ecf4defb265566462663e46d4cf0dc19a0e14470b7dd2819231481dfaeb6c2d4cfa4e0cbe43691b46f4f55182c96eea11c01a55db16402af8929caa3cb63cbd07033a1c46618f18eaa507f525727094a8b47c61e7ff02074bf2d76a6b1c0dee97421a90ad9629494c0e6b9ce75614199e0161187522e596263568d6fb093682b7de8559bff999f9febff1e5ba277b14002485ae9270d1679870acb94bcbbe702af39ede5160e43c52086001c80c3c9f0f93274f071badc971dbd7f2985dfdfdf3aef098f8cd576999031fbdd8ec0e86243f82cc18c45ac331cb0d2fcab44da5722a36f6b4edbd6ef81b308809ae3580876ff148e73e34b69cd22ebbc88a2101b1d458a7e6e4fb2f8b556e971253bfe58a58aa2a3086cc5022495bd6adaa4908d8d1bbbabe5364a5a46ea00feeeebbde18032b3051a77f81b3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82852);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0675", "CVE-2015-0676", "CVE-2015-0677");
  script_bugtraq_id(73966, 73967, 73969);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq77655");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus95290");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur21069");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150408-asa");

  script_name(english:"Cisco ASA Software Multiple Vulnerabilities (cisco-sa-20150408-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) is missing a
vendor-supplied security patch and is therefore affected by the
following vulnerabilities :

  - A flaw exists in the failover ipsec feature due to not
    properly handling failover communication messages. An
    unauthenticated attacker, sending crafted UDP packets
    over the local network to the failover interface, can
    reconfigure the failover units to gain full control.
    (CVE-2015-0675)

  - A flaw exists when handling DNS reply packets, which a
    man-in-the-middle attacker, by triggering outbound DNS
    queries and then sending crafted responses to these, can
    exploit to consume excessive memory, leading to a denial
    of service. (CVE-2015-0676)

  - A flaw exists in the XML Parser configuration when
    handling specially crafted XML messages, which a remote,
    unauthenticated attacker can use to crash the WebVPN
    component, resulting in a denial of service condition.
    (CVE-2015-0677)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150408-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ddbeb92");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco Security
Advisory cisco-sa-20150408-asa.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V' &&
  model != 'v' # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500 5000-X 6500 7600 1000V or ASAv");

flag = 0;
override = 0;
local_check = 0;
fixed_ver = "";
report = "";
report_extras = "";

# For each vulnerability, check for affected OS versions,
# set "fixed" os version, and perform any additional checks

# Determine if additional local checks can be performed
if (get_kb_item("Host/local_checks_enabled")) local_check = 1;

# #################################################
cbi = "CSCur21069";
# #################################################
temp_flag = 0;

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6)"))
{
  temp_flag++;
  fixed_ver = "9.1(6)";
}
else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(3.3)"))
{
  temp_flag++;
  fixed_ver = "9.2(3.3)";
}
else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3)"))
{
  temp_flag++;
  fixed_ver = "9.3(3)";
}

# Need to check that failover is enabled
# as well as the failover ipsec feature
if (local_check && temp_flag)
{
  temp_flag = 0;
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_failover",
    "show failover"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"Failover On", string:buf))
    {
      buf = NULL;
      buf = cisco_command_kb_item(
        "Host/Cisco/Config/show_running-config-failover",
        "show running-config failover | include ipsec"
      );
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"failover ipsec", string:buf))
        {
          temp_flag = 1;
        }
      }
      else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
    }
  }
  else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
cbi = "CSCus95290";
# #################################################
temp_flag = 0;

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.28)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.28)";
}
else if (ver =~ "^8\.6[0-9]" && check_asa_release(version:ver, patched:"8.6(1.17)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.17)";
}
else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.33)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.33)";
}
else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6)"))
{
  temp_flag++;
  fixed_ver = "9.1(6)";
}
else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(3.4)"))
{
  temp_flag++;
  fixed_ver = "9.2(3.4)";
}
else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3)"))
{
  temp_flag++;
  fixed_ver = "9.3(3)";
}

# Need to check for AnyConnect or clientless ssl vpn
# or anyconnect IKEv2 VPN
if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check for ikev2 enabled
    buf1 = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config-crypto-ikev2",
      "show running-config crypto ikev2 | include enable"
    );
    buf2 = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config-webvpn",
      "show running-config webvpn"
    );
    if (check_cisco_result(buf1))
    {
      if (preg(multiline:TRUE, pattern:"crypto ikev2 enable", string:buf1))
      {
        temp_flag = 1;
      }
    }
    else if (check_cisco_result(buf2))
    {
      if (preg(multiline:TRUE, pattern:"webvpn\senable", string:buf2))
      {
        temp_flag = 1;
      }
    }
    else if (cisco_needs_enable(buf1) || cisco_needs_enable(buf2))
    {
      temp_flag = 1;
      override = 1;
    }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
cbi = "CSCuq77655";
# #################################################
temp_flag = 0;

if (ver =~ "^7\.2[^0-9]" && check_asa_release(version:ver, patched:"7.2(5.16)"))
{
  temp_flag++;
  fixed_ver = "7.2(5.16)";
}
else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.57)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.57)";
}
else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.44)"))
{
  temp_flag++;
  fixed_ver = "8.3(2.44)";
}
else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.28)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.28)";
}
else if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.24)"))
{
  temp_flag++;
  fixed_ver = "8.5(1.24)";
}
else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.17)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.17)";
}
else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.16)"))
{
  temp_flag++;
  fixed_ver = "8.7(1.16)";
}
else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.33)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.33)";
}
else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.1)"))
{
  temp_flag++;
  fixed_ver = "9.1(6.1)";
}
else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(3.4)"))
{
  temp_flag++;
  fixed_ver = "9.2(3.4)";
}
else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3)"))
{
  temp_flag++;
  fixed_ver = "9.3(3)";
}

# Need to that a dns server is configured
# under a DNS server group
if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config_dns_server-group",
      "show running-config dns server-group"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, icase:TRUE, pattern:"name-server\s([0-9]+\.){3}[0-9]+", string:buf))
        temp_flag = 1;
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}


if (flag)
{
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
