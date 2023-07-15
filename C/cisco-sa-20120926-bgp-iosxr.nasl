#TRUSTED 381998a7cebbb2cbae9d66bc575913be5fa554fc461190b9653b923500408a23cd76b90947eed3e033e77eaf67eec6e332e97496d95e349bf84c26a9e6848451a49f20e29c2134f6408d01350b6f52059de5f5ca8a24c365a2323f31575761f4df52746b5113955f57f46f644adb37fffab6ad61a83d34e28cda820646823a138762587ddf9bd39f31e492ae4bbd95cb1be6967604b71e4c0062eecc6e45a89ad3b89ef9d950e714ae200e756e7a03033178247f6f4f508a1911938dc483453fbc95d4167aa9bd2a83e3a96fdfa604eeceebfe728c01668a65de9fab2fd356b152651e90a99e6e64522755eff3a3983c7c291d09848d04e4d59fbd436d5a1b2ecf75fc73bf72457a0d262616993476b0b98c9a703f0f5efd82119f14e93acabe8dd95788d93cd36d0a48b2c41c68fec99e8fdca08a293ca1715dc0b333ff5c8c7b60208910ed630a3a9800295c198c261295bc062e6a1c06a8e64ebf424301037bf69a8d0cfc8a3d05b7002fb11385250e6bd63390d0aed64fe45e3d08e3e1092913f7954de9aeb3a82ac84fc75ed011ed46709b9b1b4cd17da4246ec15ff8c8630de80a6b06312f8d464118c77dfdfeb8be3baa9c3114daef854a5a8684da95a97956a0c9d866b93c7aee9517abce44962c5471ab672e39f64fbb60d0715963d1a8da61f882baf2912ca1386a59e5eb8dc50a542d56bd51fa36c927880357cd
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120926-bgp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(71436);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2012-4617");
  script_bugtraq_id(55694);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt35379");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-bgp");

  script_name(english:"Cisco IOS XR Software Malformed Border Gateway Protocol Attribute Vulnerability (cisco-sa-20120926-bgp)");
  script_summary(english:"Checks the IOS XR version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description", 
    value:
"Cisco IOS XR Software contains a vulnerability in the Border Gateway
Protocol (BGP) routing protocol feature.  The vulnerability can be
triggered when the router receives a malformed attribute from a peer on
an existing BGP session.  Successful exploitation of this vulnerability
can cause all BGP sessions to reset.  Repeated exploitation may result
in an inability to route packets to BGP neighbors during reconvergence
times.  Cisco has released free software updates that address this
vulnerability.  There are no workarounds for this vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-bgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d72b44e0");
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120926-bgp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4617");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report = "";
override = 0;

cbi = "CSCtt35379";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ( version == '4.1.0' ) flag++;
if ( version == '4.1.1' ) flag++;
if ( version == '4.1.2' ) flag++;
if ( version == '4.2.0' ) flag++;
if ( version == '4.2.1' ) flag++;
if ( version == '4.2.2' ) flag++;

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE,pattern:"router bgp", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE,pattern:"address-family (ipv4|ipv6) mvpn", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE,pattern:"neighbor", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    if (temp_flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_bgp_neighbors", "show ip bgp neighbors");
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE,pattern:"neighbor", string:buf)) { flag = 1; }
      } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
    }
  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + version + '\n';

  security_hole(port:port, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
