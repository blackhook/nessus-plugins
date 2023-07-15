#TRUSTED 9f100d4709681d323213e643187c88a63c845929f3d6989ff68a78a75a5fccb225af408c14b2053652a01ace4b5adb3cada66fe4f08dc4e87f97af35a2f66c6416cd13ee4ee747ba6a0f9ae032cb2fc3c887b4ba19e35a77c1ab10b6d1b3734149a2f72495e5304245d0c8a221129e8ba027889d57db7f481314ed035ea4cfc765b5525c1f792877edf82e5a35096e0e9faeb44b5d2b300a0817b29968ee692779633f5f4f35bd9dcba333e2458b92def69fd79e427cd9fbd4157b6376c6d80a7c1d8168a30e1aed4ff52dcb5dab21d52e6697182b5a90668a8c6e6cef59758774d4586990ec0518c4311b1f67a64250c1480e549b17fea33f4b0ff231bf0a6f120e858103286ec866102cdd6542b376233dbfb5bc2fc6208ed0a93b8c096c8ac9cea9342b8c0c87b0f0ff1c7edb88bd59af2e00d112ba25a5b77bd2a935ebaadafed4787fa6d950df358a16ba7f1e2bcced9c08fe1e335832891ef3b9503d6274b5e56d79779c88dcc86ba71cd7857690e1ca3bb2bb9094275beac346de3c45b98c3e24a96f8f88d331a148cdd89fff33bd0127ad620a0b233dff5fb70d878af95889a22bd990b88f7546c9d1d3da410015a81b34587aa29f2cf82bfecd0a8381dacd8f979e89a4408d32da6193aad1cd6dabfef6737f8d1686247dabdbb92cf930187b899c8488b42b5459d31c1269bd28032018c61e0e740a183ad04270fb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99981);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2017-3876");
  script_bugtraq_id(98284);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb14441");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170503-ios-xr");

  script_name(english:"Cisco IOS XR Software Event Management Service gRPC Handling DoS (cisco-sa-20170503-ios-xr)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XR software running on the remote device is affected by a denial
of service vulnerability in the Event Management Service daemon (emsd)
due to improper handling of gRPC requests. An unauthenticated, remote
attacker can exploit this, by repeatedly sending unauthenticated gRPC
requests, to crash the device in such a manner than manual
intervention is required to recover.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170503-ios-xr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?716c8dcf");
  # https://www.networkworld.com/article/3194146/cisco-subnet/cisco-drops-critical-security-warning-on-vpn-router-3-high-priority-caveats.html#tk.rss_security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a897d8e7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb14441");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvb14441.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3876");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

cmds = make_list();

flag = 0;
override = 0;

# Known Affected: 6.1.0 and 6.1.1 with gRPC service enabled and configured
if ((version == "6.1.1" || version == "6.1.0")
  && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_include_grpc", "show run | include grpc");
  if (check_cisco_result(buf))
  {
    if ("grpc" >< buf && "!" >< buf)
    {
      cmds = make_list(cmds, "show run | include grpc");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
    override = 1;

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XR", version);
}

if (flag || override)
{
  security_report_cisco(
    port     : port,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : "CSCvb14441",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
