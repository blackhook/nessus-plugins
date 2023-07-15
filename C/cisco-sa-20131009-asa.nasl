#TRUSTED 6534141efdde973881c8cfe05d349fc3b6c90c0b40b1d9870773348ce8b3b5353ab2e925db7deccfb569823dcaf7131c670c2dcc7a28732df9ed97d2d806525745c44df6188e5b290d1f830f8946e49583146792752324e2a64479df4f24cd4dc632cb26309c7365327fa526c39287679c1c1ac1ff00acd89c05bcc6f88f8cbcc594038a943632737adeabca62c8d5f77ed0b0f5088b1438df73483fbca2325c330d3d33db79048b7d4c697def31674fbc7c2e64487dd68467df48e9268b71a026e2824290fea62a70f75b01b3b5629b5a4a2f9a774aa98a7c90300f5a284b85bbeb46ba68ced3cbaedc7ef49330d6c20747c9f4d826d32cc54ae2312c3d108755d1c5a3ad96ddf3a31280cb55beb830731bbdd95752e97ef63fe8c0827f12d34515ace94d77c51a8a2a1379d823fdb352d812d2d53750304d875d84607855bfce842ff68bced1adebc24e5fcb95da598a9d526276f1837eb87434d85b2162d22760fcd14bf624b0c31cde3afca369dfd3fcaa3abf98b61e6f28607c2e908073c12aaefcebd4e54a31083b3f295313bbff3fea3d17ae3228daa8d48c8817fe45617b048ee957c1ae9f49cbb9c3d06cf5cf984b5674496b4bbaa06f367cc0cd7635d27df391c335cfbc57fcd849c067314a879b82f36e978031ee0dea5f7a4eb5b967a62dae75f5048af286f25a5bb7016eaa85a1767f8fa70469ed3cf51f8841
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70474);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id(
    "CVE-2013-3415",
    "CVE-2013-5507",
    "CVE-2013-5508",
    "CVE-2013-5509",
    "CVE-2013-5510",
    "CVE-2013-5511",
    "CVE-2013-5512",
    "CVE-2013-5513",
    "CVE-2013-5515",
    "CVE-2013-5542"
  );
  script_bugtraq_id(
    62910,
    62911,
    62912,
    62913,
    62914,
    62915,
    62916,
    62917,
    62919,
    63202
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt36737");
  script_xref(name:"CISCO-BUG-ID", value:"CSCua22709");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub98434");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud37992");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue18975");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf52468");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug03975");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug83401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh44815");
  script_xref(name:"CISCO-BUG-ID", value:"CSCui77398");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cisco-sa-20131009-asa");

  script_name(english:"Cisco ASA Software Multiple Vulnerabilities (cisco-sa-20131009-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASA device is affected by one or more of the 
following vulnerabilities :

  - A denial of service vulnerability exists due to improper
    clearing of unused memory blocks after an AnyConnect SSL
    VPN client disconnects. (CVE-2013-3415)

  - A denial of service vulnerability exists resulting from
    an error in the code that decrypts packets transiting an
    active VPN tunnel. (CVE-2013-5507)

  - A denial of service vulnerability exists due to improper
    handling of segmented Transparent Network Substrate
    (TNS) packets. (CVE-2013-5508)

  - An authentication bypass vulnerability exists resulting
    due to an error in handling a client crafted certificate
    during the authentication phase. (CVE-2013-5509)

  - An authentication bypass vulnerability exists due to
    improper parsing of the LDAP response packet received
    from a remote AAA LDAP server. (CVE-2013-5510)

  - An authentication bypass vulnerability exists due to an
    error in the implementation of the
    authentication-certificate option. (CVE-2013-5511)

  - A denial of service vulnerability exists due to improper
    handling of a race condition during inspection of HTTP
    packets by the HTTP DPI engine. (CVE-2013-5512)

  - A denial of service vulnerability exists due to the
    improper processing of unsupported DNS over TCP packets
    by the DNS inspection engine. (CVE-2013-5513)

  - A denial of service vulnerability exists resulting from
    the improper handling of crafted HTTPS requests for
    systems configured for Clientless SSL VPN.
    (CVE-2013-5515)

  - A denial of service condition can be caused by improper
    handling of crafted ICMP packets. (CVE-2013-5542)

Note that the verification checks for the presence of CVE-2013-5513
and CVE-2013-5515 are best effort approaches and may result in
potential false positives.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131009-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d011fc2b");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31107
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efc913e7");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31103
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d97cc96");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31104
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e758053c");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31106
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f122ca71");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31102
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0960915d");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31105
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82b9bb7a");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31098
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94e50312");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31101
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8eee683f");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31100
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f18ec641");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131009-asa.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_5500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_6500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_7600");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_1000V");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
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
  model !~ '^55[0-9][0-9]' &&
  model !~ '^65[0-9][0-9]' &&
  model !~ '^76[0-9][0-9]' &&
  model !~ '^1000V'
) audit(AUDIT_HOST_NOT, "ASA 5500 5000-X 6500 7600 or 1000V");

flag = 0;
report_extras = "";
fixed_ver = "";
local_check = 0;
override = 0;

# For each vulnerability, check for affected OS versions,
# set "fixed" os version, and perform any additional checks

# Determine if additional local checks can be performed
if (
  get_kb_item("Host/local_checks_enabled") 
) local_check = 1;

# #################################################
# CSCue18975
# #################################################
cbi = "CSCue18975";
temp_flag = 0;

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(1.7)"))
{
  temp_flag++;
  fixed_ver = "9.1(1)7";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_crypto_map", "show running-config crypto map");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"crypto map .*interface", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
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
# CSCuf52468
# #################################################
cbi = "CSCuf52468";
temp_flag = 0;

# Verify additional Hardware restrictions
if (
  model != '5505' &&
  model != '5510' &&
  model != '5520' &&
  model != '5540' &&
  model != '5550'
)
{
  if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(2.6)"))
  {
    temp_flag++;
    fixed_ver = "9.0(2)6";
  }

  if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(2)"))
  {
    temp_flag++;
    fixed_ver = "9.1(2)";
  }

  if (local_check)
  {
    if (temp_flag)
    {
      temp_flag = 0;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_webvpn", "show running-config webvpn");
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"enable", string:buf))
        {
          buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_tunnel-group_AnyConnect-TG", "show running-config tunnel-group AnyConnect-TG");
          if (check_cisco_result(buf))
          {
            if (preg(multiline:TRUE, pattern:"authentication .*certificate", string:buf)) { temp_flag = 1; }
          }
          else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
        }
      } 
      else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
      if (!temp_flag)
      {
        buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_http", "show running-config http");
        if (check_cisco_result(buf))
        {
          if (
            preg(multiline:TRUE, pattern:"http server enable", string:buf) &&
            preg(multiline:TRUE, pattern:"(http authentication-certificate|ssl certificate-authentication interface)", string:buf)
          ) { temp_flag = 1; }
        }
        else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
      }
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
}

# #################################################
# CSCub98434
# #################################################
cbi = "CSCub98434";
temp_flag = 0;

if (ver =~ "^7\.0[^0-9]")
{
  temp_flag++;
  fixed_ver = "7.2.x or later";
}

if (ver =~ "^7\.1[^0-9]")
{
  temp_flag++;
  fixed_ver = "7.2.x or later";
}

if (ver =~ "^7\.2[^0-9]" && check_asa_release(version:ver, patched:"7.2(5.12)"))
{
  temp_flag++;
  fixed_ver = "7.2(5)12";
}

if (ver =~ "^8\.0[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.1[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.44)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)44";
}

if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)39";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(6)"))
{
  temp_flag++;
  fixed_ver = "8.4(6)";
}

if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.18)"))
{
  temp_flag++;
  fixed_ver = "8.5(1)18";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)12";
}

if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.6)"))
{
  temp_flag++;
  fixed_ver = "8.7(1)6";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(2.10)"))
{
  temp_flag++;
  fixed_ver = "9.0(2)10";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(2)"))
{
  temp_flag++;
  fixed_ver = "9.1(2)";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_service-policy_include_sqlnet", "show service-policy | include sqlnet");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"[Ii]nspect\s*:\s*sqlnet", string:buf)) { temp_flag = 1; }
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
# CSCug03975
# #################################################
cbi = "CSCug03975";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.46)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)46";
}

if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)39";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7)"))
{
  temp_flag++;
  fixed_ver = "8.4(7)";
}

if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.18)"))
{
  temp_flag++;
  fixed_ver = "8.5(1)18";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)12";
}

if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.7)"))
{
  temp_flag++;
  fixed_ver = "8.7(1)7";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.3)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)3";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(1.8)"))
{
  temp_flag++;
  fixed_ver = "9.1(1)8";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_policy-map", "show running-config policy-map");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"inspect dns preset_dns_map", string:buf)) { temp_flag = 1; }
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
# CSCug83401
# #################################################
cbi = "CSCug83401";
temp_flag = 0;

if (ver =~ "^7\.0[^0-9]")
{
  temp_flag++;
  fixed_ver = "7.2.x or later";
}

if (ver =~ "^7\.1[^0-9]")
{
  temp_flag++;
  fixed_ver = "7.2.x or later";
}

if (ver =~ "^7\.2[^0-9]" && check_asa_release(version:ver, patched:"7.2(5.12)"))
{
  temp_flag++;
  fixed_ver = "7.2(5)12";
}

if (ver =~ "^8\.0[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.1[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.46)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)46";
}

if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)39";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(6.6)"))
{
  temp_flag++;
  fixed_ver = "8.4(6)6";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)12";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.1)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)1";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(2.5)"))
{
  temp_flag++;
  fixed_ver = "9.1(2)5";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_tunnel-group_AnyConnect-TG", "show running-config tunnel-group AnyConnect-TG");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"override-account-disable", string:buf) && preg(multiline:TRUE, pattern:"authentication-server-group", string:buf))
      {
        temp_group  = eregmatch(string:buf, pattern:"authentication-server-group\s+([^\r\n]+)");
        buf = cisco_command_kb_item("Host/Cisco/Config/show_aaa-server_protocol_ldap", "show aaa-server protocol ldap");
        if (check_cisco_result(buf))
        {
          temp_pat = "Server Group:\s*" +  temp_group;
          if (preg(multiline:TRUE, pattern:"Server Protocol: ldap", string:buf) && preg(multiline:TRUE, pattern:temp_pat, string:buf)) { temp_flag = 1; }
        }
        else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
      }
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
# CSCtt36737
# #################################################
cbi = "CSCtt36737";
temp_flag = 0;

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(3)"))
{
  temp_flag++;
  fixed_ver = "8.4(3)";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.3)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)3";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_webvpn", "show running-config webvpn");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"svc enble", string:buf) || preg(multiline:TRUE, pattern:"anyconnect enable", string:buf)) { temp_flag = 1; }
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
# CSCud37992
# #################################################
cbi = "CSCud37992";
temp_flag = 0;

# Verify additional Hardware restrictions
if (
  model != '5505' &&
  model != '5510' &&
  model != '5520' &&
  model != '5540' &&
  model != '5550'
)
{
  if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.46)"))
  {
    temp_flag++;
    fixed_ver = "8.2(5)46";
  }

  if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
  {
    temp_flag++;
    fixed_ver = "8.3(2)39";
  }

  if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(5.5)"))
  {
    temp_flag++;
    fixed_ver = "8.4(5)5";
  }

  if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.18)"))
  {
    temp_flag++;
    fixed_ver = "8.5(1)18";
  }

  if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
  {
    temp_flag++;
    fixed_ver = "8.6(1)12";
  }

  if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.4)"))
  {
    temp_flag++;
    fixed_ver = "8.7(1)4";
  }

  if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(1.4)"))
  {
    temp_flag++;
    fixed_ver = "9.0(1)4";
  }

  if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(1.2)"))
  {
    temp_flag++;
    fixed_ver = "9.1(1)2";
  }

  if (local_check)
  {
    if (temp_flag)
    {
      temp_flag = 0;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_policy-map_type_inspect_http", "show running-config policy-map type inspect http");
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"spoof-server", string:buf)) { temp_flag = 1; }
        if (preg(multiline:TRUE, pattern:"filter java", string:buf)) { temp_flag = 1; }
        if (preg(multiline:TRUE, pattern:"filter activex", string:buf)) { temp_flag = 1; }
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
}

# #################################################
# CSCuh44815
# #################################################
cbi = "CSCuh44815";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.46)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)46";
}

if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)39";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(6.6)"))
{
  temp_flag++;
  fixed_ver = "8.4(6)6";
}

if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.18)"))
{
  temp_flag++;
  fixed_ver = "8.5(1)18";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)12";
}

if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.7)"))
{
  temp_flag++;
  fixed_ver = "8.7(1)7";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.1)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)1";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(2.6)"))
{
  temp_flag++;
  fixed_ver = "9.1(2)6";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_http", "show running-config http");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"http authentication-certificate", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE, pattern:"ssl certificate-authentication interface", string:buf)) { temp_flag = 1; }
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
# CSCua22709
# #################################################
cbi = "CSCua22709";
temp_flag = 0;

if (ver =~ "^8\.0[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.1[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.44)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)44";
}

if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)39";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(5.7)"))
{
  temp_flag++;
  fixed_ver = "8.4(5)7";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)12";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(2.6)"))
{
  temp_flag++;
  fixed_ver = "9.0(2)6";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(1.7)"))
{
  temp_flag++;
  fixed_ver = "9.1(1)7";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_webvpn", "show running-config webvpn");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"enable", string:buf)) { temp_flag = 1; }
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
# CSCui77398
# #################################################
cbi = "CSCui77398";
temp_flag = 0;

# advisory states that the issue will be fixed at least by 8.4(7.2) however,
# at the time this plugin was written, the latest known version was 8.4(7)
if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7"))
{
  temp_flag++;
  fixed_ver = "8.4(7)2";
}

# advisory states that the issue will be fixed at least by 8.7(1.8) however,
# at the time this plugin was written, the latest known version was 8.7(1.1)
if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.1)"))
{
  temp_flag++;
  fixed_ver = "8.7(1)8";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.6)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)6";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(2.8)"))
{
  temp_flag++;
  fixed_ver = "9.1(2)8";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_icmp", "show running-config icmp");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"icmp permit any", string:buf)) { temp_flag = 1; }
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }

    if (!temp_flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_ipv6", "show running-config ipv6", 0);
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"ipv6 icmp permit any", string:buf)) { temp_flag = 1; }
      }
      else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
    }

    if (!temp_flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"inspect icmp", string:buf)) { temp_flag = 1; }
      }
      else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
    }
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

if (flag)
{
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
