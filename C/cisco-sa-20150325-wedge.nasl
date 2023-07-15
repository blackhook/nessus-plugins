#TRUSTED 6d26d78615a27c0b3419d9ac07a5c2013da16cb40c78282a945c34639089ec9ba75ea05430306c0af5e88f6188987f662dedaebc18294d7f0373db5dff017416be30f987cbeb3995fd7883fa4f90441d3f238620e5dfef46d4bae733c99e06b04e445f374d1dea2ea428825edfa08e8aa48ed93dc6b9d46f97c43ca5ac5bc760ae84750a310272c40b7b246fddd87d0354d3441eae2d396c32422b1732c48c469a75df2f793750c29ef7226e1dc16fc4b202222d72f8634fc832e2ae1a2633e0a8c51165c4c1993ac59e60ee0c214a5ca0c6cfa2a78f1f6928e3e177cadfa64cc44aad37acac138697e80bd32def3bcf9a13b19cbc61d45074c678938ca667e0e6d131ff33ceac37156cc57680c14f2d25990dc76fa9fafc91a37b663c6b6e57d7d2b97be0ca935846bd57f08e2f3a7d361c4d17de409d759d06b277edd6ddc654e1316c78f5426e7785cde731144792c669f58231e441ebd8fc4171658800887c2e6a1fc3833a240b05b054632543fc8011dc72e0563a08be41e63eb01577b8dce0d31a1dc30a888d8a04ff0f99eabe81a2d421e0229d7ea960c7a63c22a8741dcfce6fd88e96802aca81acf4e16188bba93e6e774d3f6fb1417b5579b6179fd03d5fea9d1e4d3dc5fac3c3394a2a9277e6b1dec811366490e8b524d222c8ca097bb9689651eb13b0e77bfb9c577e60d8ed760ded81832e3c8426988a5a9565
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82570);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0638");
  script_bugtraq_id(73338);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsi02145");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-wedge");

  script_name(english:"Cisco IOS Software VRF ICMP Queue Wedge DoS (cisco-sa-20150325-wedge)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS software running on the remote device is affected by a
vulnerability in the Virtual Routing and Forwarding (VRF) interface
due to improperly processing crafted ICMPv4 messages, which leaves the
packet queue uncleared. A remote remote attacker can exploit this to
cause a 'queue wedge' on the interface, stopping any further packets
from being received and thus causing a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-wedge
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1223c32e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150325-wedge. Note that Cisco has released free software
updates that address this vulnerability. Workarounds that mitigate
this issue are not available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

model = get_kb_item("Host/Cisco/IOS/Model");
if (empty_or_null(model))
  model = "Unknown Cisco IOS device";

if (version == '12.2(33)IRD1') flag++;
if (version == '12.2(33)IRE3') flag++;
if (version == '12.2(44)SQ1') flag++;
if (version == '12.2(33)SXI4b') flag++;
if (version == '12.4(25e)JAM1') flag++;
if (version == '12.4(25e)JAP1m') flag++;
if (version == '12.4(25e)JAZ1') flag++;
if (version == '15.0(2)ED1') flag++;
if (version == '15.2(1)EX') flag++;
if (version == '15.2(2)GC') flag++;
if (version == '15.2(2)JA1') flag++;
if (version == '15.3(2)S2') flag++;
if (version == '15.3(3)JN') flag++;
if (version == '15.3(3)JNB') flag++;
if (version == '15.3(3)JAB1') flag++;
if (version == '15.3(3)JA1n') flag++;
if (version == '15.2(3)XA') flag++;
if (version == '15.2(3)T1') flag++;
if (version == '15.2(2)T1') flag++;
if (version == '15.2(2)T3') flag++;
if (version == '15.2(2)T2') flag++;
if (version == '15.2(2)JB1') flag++;
if (version == '15.2(2)JAX1') flag++;
if (version == '15.2(2)JB4') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_vrf", "show vrf");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\s+\S+\s+\S+\s+ipv4\s+\S+", multiline:TRUE, string:buf))
        flag = 1;
    }
    else if (cisco_needs_enable(buf))
    {
      flag = 1;
      override = 1;
    }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model       : ' + model +
      '\n  IOS Version : ' + version +
      cisco_caveat(override) +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_DEVICE_NOT_VULN, model, version);
