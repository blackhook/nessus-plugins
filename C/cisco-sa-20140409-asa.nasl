#TRUSTED 9f5c2e580afef95692119b5b7af2b271573a14463ba3d5cd6776be2134205dcb4637f6869cd87d74eeeb78a7b9832be7a545e4cca0a07809279329ef7245956fa2b556deff300281558344277b7ebc6f8d63d8889c349faf673d22ebe2dcbb28649ef6240a7b35ebf3ef630223c1aefd7fd06c8b697c6dfb907351b8c2b593b128d56d0f967d3abbc8bbffcd150ea4803cc9ffa71fcd12d907ae1a869abe3a11cd9f637d0158634ff2da79cb25a824f6c7afa38f0ffef5fc5f2a2ba541301129c7f85cbe0b7180f9d719cc86e7446c8922528f38e33ef211cd96d127c7e03e0c087d888f45c84f3c096502cc5ac719fdc0cb45adfc7056ae444fe7a481d0b0fe9bc7882fca36313f4f8270e665ce4941c8641e49f2ea5e53b85e2e2600dffcd696610d911ea3ec84b018ac4f1318d7eaf5043dfdea251b8b5fac3299327f8196d6aee4c2ea7ef585c1f2efd64b6905e0819b6ac78c1e5dc4166620d8b284756ee2a29c956cce9e524b7d7a19bc463ddb47dfe818bcb37a9525caeb4b579feedbbd7a473a88c3b0d85dd946be26447e37854290892d063a6599c9af87c34bd3d33aaad769eed6515929a6b9e29dd4e61f31fc66be023a5940bda955ba965ae03371a42ce13abbf2f36c2e05938602973c6c43ff1720992db2ddc327c3a8ae048f3457dab2128188deb901b88c4afaee79a576faeb34b44e1cab03e9bb5ba50e37
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73533);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id(
    "CVE-2014-2126",
    "CVE-2014-2127",
    "CVE-2014-2128",
    "CVE-2014-2129"
  );
  script_bugtraq_id(66745, 66746, 66747, 66748);
  script_xref(name:"CISCO-BUG-ID", value:"CSCua85555");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh44052");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj33496");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul70099");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140409-asa");

  script_name(english:"Cisco ASA Software Multiple Vulnerabilities (cisco-sa-20140409-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASA device is affected by one or more of the
following vulnerabilities :

  - An issue exists in the Adaptive Security Device Manager
    (ADSM) due to improper privilege assignment to users
    with a privilege level of zero. This issue allows an
    authenticated, remote attacker to gain administrative
    privileges. (CVE-2014-2126)

  - An issue exists in the SSL VPN portal when the
    Clientless SSL VPN feature is used due to improper
    handling of management session information. An
    authenticated, remote attacker can exploit this to gain
    administrative privileges. (CVE-2014-2127)

  - An issue exists in the SSL VPN feature due to improper
    handling of authentication cookies. An unauthenticated,
    remote attacker can exploit this to bypass
    authentication, resulting in unauthorized access to
    internal network resources. (CVE-2014-2128)

  - An issue exists in the SIP inspection engine due to
    improper handling of SIP packets. An unauthenticated,
    remote attacker can exploit this to cause memory
    exhaustion, resulting in a denial of service.
    (CVE-2014-2129)

Note that that the verification check for the presence of
CVE-2014-2128 is a best effort approach and may result in potential
false positives.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140409-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?687b1a20");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco Security
Advisory cisco-sa-20140409-asa.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_5500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_6500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_7600");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_1000V");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

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
# CSCuj33496
# #################################################
cbi = "CSCuj33496";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.47)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)47";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.5)"))
{
  temp_flag++;
  fixed_ver = "8.4(7)5";
}

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.11)"))
{
  temp_flag++;
  fixed_ver = "8.7(1)11";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.10)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)10";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(3.4)"))
{
  temp_flag++;
  fixed_ver = "9.1(3)4";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check if HTTP is enabled
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config_http",
      "show running-config http"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"http server enable", string:buf))
      {
        # Check if a user has been assigned privilege level 0
        buf = cisco_command_kb_item(
          "Host/Cisco/Config/show_running-config_username_include_privilege_0",
          "show running-config username | include privilege 0"
        );
        if (check_cisco_result(buf))
        {
          if (preg(multiline:TRUE, pattern:"privilege 0$", string:buf))
            temp_flag = 1;
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
# CSCul70099
# #################################################
cbi = "CSCul70099";
temp_flag = 0;

if (ver =~ "^8\.[01][^0-9]")
{
  temp_flag++;
  fixed_ver = "This branch is no longer supported. Refer to the vendor for a fix.";
}

else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.48)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)48";
}

else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.40)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)40";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.9)"))
{
  temp_flag++;
  fixed_ver = "8.4(7)9";
}

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.13)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)13";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.1)"))
{
  temp_flag++;
  fixed_ver = "9.0(4)1";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(4.3)"))
{
  temp_flag++;
  fixed_ver = "9.1(4)3";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check if SSL VPN (WebVPN) feature is enabled
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config_webvpn",
      "show running-config webvpn"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"enable", string:buf))
        temp_flag = 1;
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n    Cisco bug ID      : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCua85555
# #################################################
cbi = "CSCua85555";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.47)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)47";
}

else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.40)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)40";
}

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.3)"))
{
  temp_flag++;
  fixed_ver = "8.4(7)3";
}

else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.13)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)13";
}

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.8)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)8";
}

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(3.2)"))
{
  temp_flag++;
  fixed_ver = "9.1(3)2";
}


if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check if SSL VPN (WebVPN) feature is enabled
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config_webvpn",
      "show running-config webvpn"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"enable", string:buf))
      {
        # Versions 8.2.x and 8.3.x are not affected if HostScan feature is enabled AND
        # certificate-only authentication is used for SSL VPN authentication
        if (ver =~ "^8\.[23][^0-9]")
        {

          buf = cisco_command_kb_item(
            "Host/Cisco/Config/show-webvpn-csd-hostscan",
            "show webvpn csd hostscan"
          );
          if (check_cisco_result(buf))
          {
            if (!preg(multiline:TRUE, pattern:"and enabled", string:buf))
            {

              buf = cisco_command_kb_item(
                "Host/Cisco/Config/show_running-config_all_tunnel-group",
                "show running-config all tunnel-group"
              );
              if (check_cisco_result(buf))
              {
                if (preg(multiline:TRUE, pattern:"authentication (aaa )?certificate", string:buf))
                  temp_flag = 1;
              }
              else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
            }
          }
          else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
        }

        # Check if 'authorization-required' is enabled in *ANY* tunnel group
        buf = cisco_command_kb_item(
          "Host/Cisco/Config/show_running-config_all_tunnel-group",
          "show running-config all tunnel-group"
        );
        if (check_cisco_result(buf))
        {
          if (!preg(multiline:TRUE, pattern:"^\s*authorization-required", string:buf))
            temp_flag = 1;
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
    '\n    Cisco bug ID      : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCuh44052
# #################################################
cbi = "CSCuh44052";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.48)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)48";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(6.5)"))
{
  temp_flag++;
  fixed_ver = "8.4(6.5)";
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
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_service-policy-include-sip",
      "show service-policy | include sip"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, icase:TRUE, pattern:"Inspect: sip", string:buf))
        temp_flag = 1;
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n    Cisco bug ID      : ' + cbi +
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
