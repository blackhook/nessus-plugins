#TRUSTED 0e6ca56d788487424dfd30404d17e96814d59443ddf855332a8507007fe05efc1fe0b472233b7923f26576f5c76c5eeeb9e25c5b8a956768b410405c6dd9c583f9e4f39447abbc368cad3fa36d316046123ea3b9f040e1936321573acaf15251344e9fb933dcf9292ecbced66082237e0e79bb2cd23be676d8446fac2d5ea0f80f4abe57d4dc5e3612232a4e44abb4cd05464ac669dfe2312dcceee563dadc7ed487bed6645dffcb80e827c9b4c6d7a78c410e574fcb117bf8435d1edcf338aa2913179ba67be4f541c396be8dcdf438e7b86febadd360ecf8dcb3b11bc0b975ebf711e669952c490ff3ac8ef2c8ea206b9d2077829b9cc225b8b60f6ffec0fc30912c7f6c9d53773fa286ccefd333a365788f5061f3d2a967e07ee0372769cd1dd8e8284d94e01d21383736a96e2524feeeb9757b7265924d01a6fc606d380d7b0ca138707f98426af30dbd855fb7d76fc1e5e179c19ea9f48dec169709dbb632f81245f69aba69a174f3c30f6fcb55b4b48341dff0ac6bcaf205ce9ba4aecc8c2316f4fb5fc57a74c0858675eb6e244581cd402eee5aa2ab5e1e3dd1bdef7b951b62469985268659ca43ae7429f3047263756a8235217caef4c89c13c7bf1a86cb0c40fd1b60e597f296a049d477da94fe584c5e3c33a78e09576faca88010a3371d2d77eab4fb17a9505953211e8de47493a7568aca07a7eb38a20a2d6768
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73340);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-2108");
  script_bugtraq_id(66471);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui88426");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ikev2");

  script_name(english:"Cisco IOS XE Software Internet Key Exchange Version 2 (IKEv2) Denial of Service (cisco-sa-20140326-ikev2)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the Internet Key Exchange Version 2 (IKEv2) module.
An unauthenticated, remote attacker could potentially exploit this
issue by sending a malformed IKEv2 packet resulting in a denial of
service.

Note that this issue only affects hosts when Internet Security
Association and Key Management Protocol (ISAKMP) is enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec115086");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33346");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-ikev2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}


include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

override = 0;
report = "";
cbi = "CSCui88426";
fixed_ver = "";

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# 3.2xS
if (ver == '3.2.0S' || ver == '3.2.1S' || ver == '3.2.2S')
         fixed_ver = '3.7.5S';
# 3.3xS
else if (ver == '3.3.0S' || ver == '3.3.1S' || ver == '3.3.2S')
         fixed_ver = '3.7.5S';
# 3.4xS
else if (ver == '3.4.0S' || ver == '3.4.1S' || ver == '3.4.2S' || ver == '3.4.3S' || ver == '3.4.4S' || ver == '3.4.5S' || ver == '3.4.6S')
         fixed_ver = '3.7.5S';
# 3.6xS
else if (ver == '3.6.0S' || ver == '3.6.1S' || ver == '3.6.2S')
         fixed_ver = '3.7.5S';
# 3.7xS
else if (ver == '3.7.0S' || ver == '3.7.1S' || ver == '3.7.2S' || ver == '3.7.3S' || ver == '3.7.4S')
         fixed_ver = '3.7.5S';

# 3.3xSG
else if (ver == '3.3.0SG' || ver == '3.3.1SG' || ver == '3.3.2SG')
         fixed_ver = '3.5.2E';
# 3.4xSG
else if (ver == '3.4.0SG' || ver == '3.4.1SG' || ver == '3.4.2SG')
         fixed_ver = '3.5.2E';
# 3.5xS
else if (ver == '3.5.0S' || ver == '3.5.1S' || ver == '3.5.2S')
         fixed_ver = '3.5.2E';
# 3.5xE
else if (ver == '3.5.0E' || ver == '3.5.1E')
         fixed_ver = '3.5.2E';

# 3.3xXO
else if (ver == '3.3.0XO)')
         fixed_ver = '3.6.0E';

# 3.8xS
else if (ver == '3.8.0S' || ver == '3.8.1S' || ver == '3.8.2S')
         fixed_ver = '3.10.1S';
# 3.9xS
else if (ver == '3.9.0S' || ver == '3.9.1S')
         fixed_ver = '3.10.1S';
# 3.10xS
else if (ver == '3.10.0S')
         fixed_ver = '3.10.1S';


if (fixed_ver) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"17\s[^\r\n]*\s(500|4500|848|4848)", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_subsys", "show subsys");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ikev2\s+Library", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
