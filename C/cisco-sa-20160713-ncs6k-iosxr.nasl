#TRUSTED 277efb67fe9173c31188551013f227d7cad8036cd712afe43956bf908276d28f2296b340230b029b1368bdfea62e7fbf780496277969363c403dc61e560eebd17c997624df602c080effd6b1c4806d9460c8a755e93e232d661de67f9af6636b55f0d7ee5fcfc0a40214029ddb6b3fc0c6691be07c3dfaf3d76dce2e3d769941cd271579ecff52319611233d656a9989ae3ce2ab47cd6ba316b4ef87c2bfd2b203bd59878bdccb40dd1b9bb2b35d48c5f0baeeebdf982caec1f15c7682b3b62e2771baa74be743e98d64a8b83acbc17bc16d7b68d0656429a2308a75fa570bc4dfdd6b2d6833aee148d155819db8fa1ea417c5a64db1c8c3d291b719b707c1884d2e154d129421a4de65e2675c39cc586480fd575a8cf9c99fdeeafca4436cbfaefca3a209cb75fca7899c42273dc164cb018895af5cdc726dc75802dc06cf926a303db5bf9b567eeb0cf517b64417319961f5f7a304881247fe8574eb1d1159f948c73683d01f791ea2cc8d62b7c3e71da2873eaeb8aa6437d9883f54ef2a57518e9f5401c385cfad1c43c771bd44466403f5ba5c6874e73b2a15c0d75e13aa377769cd05e5139105d3491b169cff79e884bdb2fd120d8777353ad8006c9757a2143f2735bec6ef737a3fd2f7b58be3d6f185abcd5c21463c11231713b230c168c2e20cfa1d84086ba0f5798f17ae03505b5c38bfdbf71cd87981a9c6b00f70
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93563);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2016-1426");
  script_bugtraq_id(91748);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160713-ncs6k");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux76819");

  script_name(english:"Cisco IOS XR NCS 6000 Packet Timer Leak DoS (cisco-sa-20160713-ncs6k)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS XR running on the remote NCS 6000 device is
affected by a denial of service vulnerability due to improper
management of system timer resources. An unauthenticated, remote
attacker can exploit this, via numerous management connections to the
affected device, to consume resources, resulting in a nonoperational
state and eventual reload of the Route Processor.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160713-ncs6k
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87b0a91e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux76819");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco advisory
cisco-sa-20160713-ncs6k.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1426");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");
  script_require_ports("CISCO/model", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
model = get_kb_item("CISCO/model");
if (model)
{
  if (model !~ "^cisco([Nn]cs|NCS)-?(600[08]|6k)")
    audit(AUDIT_HOST_NOT, "an affected model");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("NCS6K"    >!< model &&
      "NCS6008"  >!< model &&
      "NCS-6000" >!< model &&
      "NCS-6008" >!< model
     )
    audit(AUDIT_HOST_NOT, "an affected model");
}

# Affected versions include :
#  - 5.0.0-5.0.1
#  - 5.1.0-5.1.3
#  - 5.2.0-5.2.5
if (version !~ "^5\.(0\.[01]|1\.[0-3]|2\.[0-5])([^0-9]|$)")
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

missing_pie  = '';

# Cisco SMUs per version (where available)
pies = make_array(
  '5.0.1', 'ncs6k-5.0.1.CSCux76819',
  '5.2.1', 'ncs6k-5.2.1.CSCux76819',
  '5.2.3', 'ncs6k-5.2.3.CSCux76819',
  '5.2.4', 'ncs6k-5.2.4.CSCux76819',
  '5.2.5', 'ncs6k-5.2.5.CSCux76819'
);

if (get_kb_item("Host/local_checks_enabled"))
{
  # Check for patches; only specific versions
  if (!isnull(pies[version]))
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_install_package_all", "show install package all");
    if (check_cisco_result(buf))
    {
      if (pies[version] >!< buf)
        missing_pie = pies[version];
      else audit(AUDIT_HOST_NOT, "affected because patch "+pies[version]+" is installed");
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  # Check if SSH, SCP, or SFTP is configured for management access
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ("ssh server v2" >!< buf)
      audit(AUDIT_HOST_NOT, "affected because SSH / SCP / and SFTP are not enabled for management access");
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

security_report_cisco(
  port     : port,
  severity : SECURITY_HOLE,
  override : override,
  version  : version,
  bug_id   : 'CSCux76819',
  cmds     : make_list('show running-config'),
  pie      : missing_pie
);
