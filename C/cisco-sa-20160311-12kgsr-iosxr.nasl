#TRUSTED 26619909d741fbf3f7b5fba99e27f5e72ce89ce48c3743ebaeb07962ad456cff517c2ba3a527bd114f0394e15fac05718d0491bc954d224d8052cf5cea0ba000b602779131d5bae3c7bcf4023eb011bd4638319b80b92a6dfc3d4d277e017ea5affdc8cc3d82142af29232695b74fa1db043d6aa8374b9c23a1939643e1438268712fc756105a925dfa45862e09568816c5cc2835297bf4ef975609a5a3d18c0e58732af15a90dc8526303c2fddde8277938ecd142c317bd16179031f17b0f16d1a289bf3c52ec82b6a9ce5dab5f4bfd37c16de317c30cf069fc3d79677cc5371a51be4d15a21e0100263544aee64338e9df00aa8c839bf2dcd2791a38832208ea08ad24ce5f9f8c3cdba0daba055819b0a696f61d8332f21bbdd535fb2a1624cb1fa2397cab5178d366b8fe231f73e450916c4d455ce3475c47a11071accb37e46f98467605b515886f4b990478ebe5c7074891045ce715244cb6c731b534f56347cbabd936ab2ccaf61c70539f2dead65da03df5948dcecb84cbc191c8af93f14e15f5ec18422f7b1becd1e2ed3804ead0138709e0ae785643bd09fe31af3f41da24016ffdeba904f6a79f7c3f7077a74d7fb1330622a13f9838683d2be9358bb55d18e80a354dc7441a66447359c1e34490c5cf8cadbc43ed3734b0aa2b1049d3c86236098a9f3edaa357e347147ce657bab78538adce5bfbbb167aecc75f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90527);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2016-1361");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv17791");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw56900");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160311-gsr");

  script_name(english:"Cisco IOS XR GSR 12000 Port Range BFD DoS (cisco-sa-20160311-gsr)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XR device is a Gigabit Switch Router (GSR)
12000 Series router model and is a version that is missing a
vendor-supplied security patch. It is, therefore, affected by a denial
of service vulnerability in the ASIC UDP ingress receive function due
to improper validation for the presence of a Bidirectional Forwarding
Detection (BFD) header on the UDP packet. An unauthenticated, remote
attacker can exploit this to cause a line-card to unexpectedly restart
by sending to the affected device a specially crafted UDP packet with
a specific UDP port range and Time-to-Live field.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160311-gsr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07a86a86");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20160311-gsr.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1361");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = FALSE;
override = FALSE;

cbi = "CSCuv17791 / CSCuw56900";

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
model    = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (model !~ "^12[0-9]{3}([^0-9])")
  audit(AUDIT_HOST_NOT, "Cisco 12000 Series");

# Specific versions affected according to Cisco
if (
  version =~ "^3\.3\.3([^0-9])"     ||
  version =~ "^3\.4\.[1-3]([^0-9])" ||
  version =~ "^3\.5\.[2-4]([^0-9])" ||
  version =~ "^3\.6\.[0-3]([^0-9])" ||
  version =~ "^3\.7\.[0-1]([^0-9])" ||
  version =~ "^3\.8\.[0-4]([^0-9])" ||
  version =~ "^3\.9\.[0-2]([^0-9])" ||
  version =~ "^4\.0\.[0-3]([^0-9])" ||
  version =~ "^4\.1\.[0-2]([^0-9])" ||
  version =~ "^4\.2\.[0-4]([^0-9])" ||
  version =~ "^4\.3\.[0-2]([^0-9])"
) flag = TRUE;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XR", version);

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  # System has to contain serial network interfaces
  buf = get_kb_item("Host/Cisco/show_ver");
  if (!preg(multiline:TRUE, pattern:"^\d+\s+Serial network interface", string:buf))
    flag = FALSE;

  # Specifically bfd ipv6 checksum MUST be disabled to not be affected
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (flag && check_cisco_result(buf))
  {
    if(preg(multiline:TRUE, pattern:"^bfd ipv6 checksum disable", string:buf))
      flag = FALSE;
  }
  else if (flag && cisco_needs_enable(buf))
  {
    flag = TRUE;
    override = TRUE;
  }
}

if (!flag)
  audit(AUDIT_HOST_NOT, "affected");

# The fix is to have 4.3.2 plus a vendor supplied SMU
# so 4.3.2 doesn't necessarily mean that the issue isn't
# fixed
if (flag && version =~ "^4\.3\.2([^0-9])" && report_paranoia < 2)
  audit(AUDIT_PARANOID);

report = "";
if (report_verbosity > 0)
{
  order  = make_list('Cisco bug ID', 'Installed release', 'Fixed version');
  report = make_array(
    order[0], cbi,
    order[1], version,
    order[2], '4.3.2 with Cisco SMU'
  );
  report = report_items_str(report_items:report, ordered_fields:order);
}
security_warning(port:port, extra:report+cisco_caveat(override));

