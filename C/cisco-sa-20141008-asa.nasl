#TRUSTED 56e4c25732c52db563d1c8388b1ff461ba173cd054554f223287ec161c1b05c94f9566cf061011aed7f3cc43c021310e4bef99bbb1f06688c9a2102c8caa702dc3b6daa9de2a5f049dd71b786307eea16c8aeebbba23d9aa1e4ff7349d8901f2a9e56de09bde10be227dc5c98c3acd5aee8d4a69a38030bc60813566a7a3efb1c2d2c66c2f124d6cf899493b16ec979e8f3ce3c3988ef51efe051cbb6ea7d0340cae417c3e1c5e7a776153be968ac78efacb563a8441c9d55307860e5485ed02922143077f7994742adf0f5859e46ef51855d5995a117a9c3ae00e8cb559563a6c68c057b15a5fa87989ec1109b0d0c006dd5dda710513dae02d87b44a30e65ae8fe360bcbde022a19d6153c339a438856e6eed775fb32448fc4e23da13b24d3de295a93dd0b7efa371635cb07bb7a7b6ea47077e37dc94ea4ed52ae2d8084800c778b2b33e79d0f382981c099d141967f9d62f48f3162a7fea5e26355000a68e591602bdcaf60f011901fc2959ab38455d8e565b97b62faade3004118ce70951651f7d2e8947353c565303ea62dc1bd312937b5eadb8152336059cd74616009a51ec09ae20b0e03eb7f369670b2bd56e3e7441f08489cab93f53b47004cd022ddcd06d0fb6c7a5fe75b162ce2944624a1edeca9f57d53ddf4d3add5439b87e38a6766674975bff57c8728106bc43faeb9550e8577cf3499753e50b997774366
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78240);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id(
    "CVE-2014-3382",
    "CVE-2014-3383",
    "CVE-2014-3384",
    "CVE-2014-3385",
    "CVE-2014-3386",
    "CVE-2014-3387",
    "CVE-2014-3388",
    "CVE-2014-3389",
    "CVE-2014-3390",
    "CVE-2014-3391",
    "CVE-2014-3392",
    "CVE-2014-3393",
    "CVE-2014-3394"
  );
  script_bugtraq_id(
    70294,
    70295,
    70296,
    70297,
    70298,
    70299,
    70300,
    70301,
    70302,
    70303,
    70305,
    70306,
    70309
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCum46027");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul36176");
  script_xref(name:"CISCO-BUG-ID", value:"CSCum96401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCum00556");
  script_xref(name:"CISCO-BUG-ID", value:"CSCum56399");
  script_xref(name:"CISCO-BUG-ID", value:"CSCun11074");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo68327");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq28582");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq41510");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq47574");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq52661");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq29136");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup36829");
  script_xref(name:"CISCO-BUG-ID", value:"CSCun10916");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20141008-asa");

  script_name(english:"Cisco ASA Software Multiple Vulnerabilities (cisco-sa-20141008-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASA device is affected by one or more of the
following vulnerabilities :

  - A flaw exists in the SQL*NET Inspection Engine due to
    improper handling of SQL REDIRECT packets. An attacker
    can exploit this vulnerability by sending a crafted
    sequence of REDIRECT packets through the affected
    system. This can cause the device to reload.
    (CVE-2014-3382)

  - A flaw exists in the IKE code that can allow an
    unauthenticated, remote attacker to cause the device to
    reload. This issue is due to the improper validation of
    UDP packets. (CVE-2014-3383)

  - A flaw exists in the IKEv2 code that can allow an
    unauthenticated, remote attacker to cause the device to
    reload. This issue is caused by the improper handling of
    crafted IKEv2 packets. (CVE-2014-3384)

  - A flaw exists in Health and Performance Monitoring for
    ASDM functionality that allows an unauthenticated,
    remote attacker to cause the reload of the device. This
    issue is caused by a race condition in the operation of
    the HPM functionality. An attacker can be able to
    exploit this by sending a large number of half-open
    simultaneous connections to the device. (CVE-2014-3385)

  - A flaw exists in the GPRS Tunneling Protocol Inspection
    Engine that can allow an unauthenticated, remote
    attacker to cause a reload of the device. This issue is
    caused by improper handling of GTP packets when sent in
    a specific sequence. (CVE-2014-3386)

  - A flaw exists in the SunRPC Inspection Engine that can
    allow an unauthenticated, remote attacker to cause a
    reload of the device. This issue is caused by improper
    validation of specially crafted SunRPC packets.
    (CVE-2014-3387)

  - A flaw exists in the DNS Inspection Engine that can
    allow an unauthenticated, remote attacker to cause a
    reload of the affected system. This issue is caused by
    the improper validation of crafted DNS packets.
    (CVE-2014-3388)

  - A flaw exists in the VPN failover component that can
    allow an authenticated, remote attacker to send
    configuration commands to the standby units. This is
    caused by an improper implementation of the internal
    filter for packets coming from an established VPN
    tunnel. (CVE-2014-3389)

  - A flaw exists in the VNMC component that allows an
    authenticated, local attacker to access the underlying
    operating system as the root user. This issue is caused
    by the improper sanitation of user-supplied input.
    (CVE-2014-3390)

  - A flaw exists in the function that exports environmental
    variables that allows an authenticated, local attacker
    to inject arbitrary commands. (CVE-2014-3391)

  - A flaw exists in the Clientless SSL VPN Portal feature
    that allows an unauthenticated, remote attacker to
    access arbitrary memory. This issue is caused by the
    improper sanitation of user-supplied input.
    (CVE-2014-3392)

  - A flaw exists in the Clientless SSL VPN Portal
    customization framework that allows an unauthenticated,
    remote attacker to modify the content of the portal
    interface. This can lead to the compromise of user
    credentials, cross-site scripting attacks, and other
    types of web attacks on the client using the system.
    This is caused by the improper implementation of
    authentication checks. (CVE-2014-3393)

  - A flaw exists in the Smart Call Home feature that allows
    an unauthenticated, remote attacker to bypass digital
    certificate validation if any feature that uses digital
    certificates is configured on the affected system.
    (CVE-2014-3394)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141008-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bc6432e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco Security
Advisory cisco-sa-20141008-asa.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

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

# Verify that we are targeting an affected hardware model
#   Cisco ASA 5500 Series Adaptive Security Appliances
#   Cisco ASA 5500-X Next Generation Firewall
#   Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches
#   Cisco 7600 Series Routers
#   Cisco ASA 1000V Cloud Firewall
if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V'
) audit(AUDIT_HOST_NOT, "ASA 5500 5000-X 6500 7600 or 1000V");

flag = 0;
override = 0;
local_check = 0;
fixed_ver = "";
report = "";
report_extras = "";

# For each vulnerability, check for affected OS versions,
# set "fixed" os version, and perform any additional checks

# Determine if additional local checks can be performed
if ( get_kb_item("Host/local_checks_enabled") ) local_check = 1;

# #################################################
# CSCum46027
# #################################################
cbi = "CSCum46027";
temp_flag = 0;

# Vulnerable version information pulled from cisco-sa-20141008-asa
if (ver =~ "^7\.2[^0-9]" && check_asa_release(version:ver, patched:"7.2(5.13)"))
{
  temp_flag++;
  fixed_ver = "7.2(5.13)";
}

else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.50)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.50)";
}

else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.42)"))
{
  temp_flag++;
  fixed_ver = "8.3(2.42)";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.15)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.15)";
}

else if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.21)"))
{
  temp_flag++;
  fixed_ver = "8.5(1.21)";
}

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.14)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.14)";
}

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.13)"))
{
  temp_flag++;
  fixed_ver = "8.7(1.13)";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.5)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.5)";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.1)"))
{
  temp_flag++;
  fixed_ver = "9.1(5.1)";
}


if (local_check && temp_flag)
{
  temp_flag = 0;
  # Check for sqlnet enabled
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_service-policy-include-sqlnet",
    "show service-policy | include sqlnet"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"Inspect: sqlnet", string:buf)) temp_flag = 1;
  }
  else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCul36176
# #################################################
cbi = "CSCul36176";
temp_flag = 0;

if (
  ver =~ "^9\.1[^0-9]" &&
  check_asa_release(version:ver, patched:"9.1(5.1)") &&
  cisco_gen_ver_compare(a:ver, b:'9.1(4.3)') >= 0
)
{
  temp_flag++;
  fixed_ver = "9.1(5.1)";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check for a configured crypto map
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config_crypto-map",
      "show running-config crypto map | include interface"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"crypto map", string:buf))
        temp_flag = 1;
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCum96401
# #################################################
cbi = "CSCum96401";
temp_flag = 0;

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.15)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.15)";
}

else if (ver =~ "^8\.6[0-9]" && check_asa_release(version:ver, patched:"8.6(1.14)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.14)";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.8)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.8)";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.1)"))
{
  temp_flag++;
  fixed_ver = "9.1(5.1)";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check for ikev2 enabled
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config-crypto-ikev2",
      "show running-config crypto ikev2 | include enable"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"crypto ikev2 enable", string:buf))
      {
        temp_flag = 1;
      }
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCum00556
# #################################################
cbi = "CSCum00556";
temp_flag = 0;

if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.42)"))
{
  temp_flag++;
  fixed_ver = "8.3(2.42)";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.11)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.11)";
}

else if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.19)"))
{
  temp_flag++;
  fixed_ver = "8.5(1.19)";
}

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.13)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.13)";
}

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.11)"))
{
  temp_flag++;
  fixed_ver = "8.7(1.11)";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.8)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.8)";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(4.5)"))
{
  temp_flag++;
  fixed_ver = "9.1(4.5)";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check for HPM enabled
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config-include-hpm",
      "show running-config | include hpm"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, icase:TRUE, pattern:"hpm topn enable", string:buf))
        temp_flag = 1;
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCum56399
# #################################################
cbi = "CSCum56399";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.51)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.51)";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.15)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.15)";
}

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.13)"))
{
  temp_flag++;
  fixed_ver = "8.7(1.13)";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.8)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.8)";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.1)"))
{
  temp_flag++;
  fixed_ver = "9.1(5.1)";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check for gtp inspection enabled
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_service-policy-include-gtp",
      "show service-policy | include gtp"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, icase:TRUE, pattern:"Inspect: gtp", string:buf))
        temp_flag = 1;
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCun11074
# #################################################
cbi = "CSCum11074";
temp_flag = 0;

if (ver =~ "^7\.2[^0-9]" && check_asa_release(version:ver, patched:"7.2(5.14)"))
{
  temp_flag++;
  fixed_ver = "7.2(5.14)";
}

else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.51)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.51)";
}

else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.42)"))
{
  temp_flag++;
  fixed_ver = "8.3(2.42)";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.23)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.23)";
}

else if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.21)"))
{
  temp_flag++;
  fixed_ver = "8.5(1.21)";
}

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.14)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.14)";
}

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.13)"))
{
  temp_flag++;
  fixed_ver = "8.7(1.13)";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.5)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.5)";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.3)"))
{
  temp_flag++;
  fixed_ver = "9.1(5.3)";
}

if (local_check && temp_flag)
{
  temp_flag = 0;
  # Check for dns inspection enabled
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_service-policy-include-sunrpc",
    "show service-policy | include sunrpc"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"Inspect: sunrpc", string:buf)) temp_flag = 1;
  }
  else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCuo68327
# #################################################
cbi = "CSCuo68327";
temp_flag = 0;

if (
  ver =~ "^9\.0[^0-9]" &&
  check_asa_release(version:ver, patched:"9.0(4.13)") &&
  cisco_gen_ver_compare(a:ver, b:'9.0(4.8)') >= 0
)
{
  temp_flag++;
  fixed_ver = "9.0(4.13)";
}

else if (
  ver =~ "^9\.1[^0-9]" &&
  check_asa_release(version:ver, patched:"9.1(5.7)") &&
  cisco_gen_ver_compare(a:ver, b:'9.1(5.2)') >= 0
)
{
  temp_flag++;
  fixed_ver = "9.1(5.7)";
}

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(2)"))
{
  temp_flag++;
  fixed_ver = "9.2(2)";
}

if (local_check && temp_flag)
{
  temp_flag = 0;
  # Determine if high availability mode is enabled
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_service-policy-include-dns",
    "show service-policy | include dns"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"Inspect: dns", string:buf)) temp_flag = 1;
  }
  else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCuq28582
# #################################################
cbi = "CSCuq28582";
temp_flag = 0;

if (ver =~ "^7\.2[^0-9]" && check_asa_release(version:ver, patched:"7.2(5.15)"))
{
  temp_flag++;
  fixed_ver = "7.2(5.15)";
}

else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.51)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.51)";
}

else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.42)"))
{
  temp_flag++;
  fixed_ver = "8.3(2.42)";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.23)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.23)";
}

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.15)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.15)";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.24)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.24)";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.12)"))
{
  temp_flag++;
  fixed_ver = "9.1(5.12)";
}

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(2.6)"))
{
  temp_flag++;
  fixed_ver = "9.2(2.6)";
}

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(1.1)"))
{
  temp_flag++;
  fixed_ver = "9.3(1.1)";
}

if (local_check && temp_flag)
{
  temp_flag = 0;
  # Determine if high availability mode is enabled
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_failover",
    "show failover"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"Failover On", string:buf)) temp_flag = 1;
  }
  else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCuq41510 and CSCuq47574
# #################################################
cbi = "CSCuq41510 and CSCuq47574";
temp_flag = 0;

if (ver =~ "^8\.7" && check_asa_release(version:ver, patched:"8.7(1.14)"))
{
  temp_flag++;
  fixed_ver = "8.7(1.14)";
}

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(2.8)"))
{
  temp_flag++;
  fixed_ver = "9.2(2.8)";
}

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(1.1)"))
{
  temp_flag++;
  fixed_ver = "9.3(1.1)";
}

# According to advisory, all affected versions are affected, no local checks needed
if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCtq52661
# #################################################
cbi = "CSCtq52661";
temp_flag = 0;

if (ver =~ "^8\.[35][^0-9]")
{
  temp_flag++;
  fixed_ver = "Not available. See advisory for upgrade details.";
}

else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.52)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.52)";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(3)"))
{
  temp_flag++;
  fixed_ver = "8.4(3)";
}

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.13)"))
{
  temp_flag++;
  fixed_ver = "8.7(1.13)";
}

# According to advisory, all affected versions are affected, no local checks needed
if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCuq29136
# #################################################
cbi = "CSCuq29136";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.51)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.51)";
}

else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.42)"))
{
  temp_flag++;
  fixed_ver = "8.3(2.42)";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.23)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.23)";
}

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.15)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.15)";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.24)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.24)";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.12)"))
{
  temp_flag++;
  fixed_ver = "9.1(5.12)";
}

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(2.8)"))
{
  temp_flag++;
  fixed_ver = "9.2(2.8)";
}

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(1.1)"))
{
  temp_flag++;
  fixed_ver = "9.3(1.1)";
}

if (local_check && temp_flag)
{
  temp_flag = 0;
  # Check for webvpn enabled
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config-webvpn",
    "show running-config webvpn"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"enable", string:buf)) temp_flag = 1;
  }
  else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCup36829
# #################################################
cbi = "CSCup36829";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.51)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.51)";
}

else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.42)"))
{
  temp_flag++;
  fixed_ver = "8.3(2.42)";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.23)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.23)";
}

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.14)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.14)";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.24)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.24)";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.12)"))
{
  temp_flag++;
  fixed_ver = "9.1(5.12)";
}

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(2.4)"))
{
  temp_flag++;
  fixed_ver = "9.2(2.4)";
}

if (local_check && temp_flag)
{
  temp_flag = 0;
  # Check for webvpn enabled
  # Note: There is an additional condition for this which we
  #   cannot check for. We are unable to tell if a preview of
  #   a customization object has been done.
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config-webvpn",
    "show running-config webvpn"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"enable", string:buf)) temp_flag = 1;
  }
  else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
}

if (temp_flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCun10916
# #################################################
cbi = "CSCun10916";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.50)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.50)";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.15)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.15)";
}

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.14)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.14)";
}

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.13)"))
{
  temp_flag++;
  fixed_ver = "8.7(1.13)";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.8)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.8)";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.1)"))
{
  temp_flag++;
  fixed_ver = "9.1(5.1)";
}

if (local_check && temp_flag)
{
  temp_flag = 0;
  # Check for SCH enabled
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config-crypto-ca-trustpoint-_SmartCallHome_ServerCA",
    "show running-config crypto ca trustpoint _SmartCallHome_ServerCA"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"crl configure", string:buf)) temp_flag = 1;
  }
  else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

################################

if (flag)
{
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
