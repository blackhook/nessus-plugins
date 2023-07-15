#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91321);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2016-1407");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160519-ios-xr");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux95576");

  script_name(english:"Cisco IOS XR < 6.1.1 on ASR 9000 LPTS DoS");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS XR running on the remote ASR 9000 device is
prior to 6.1.1. It is, therefore, affected by a denial of service
vulnerability in the Local Packet Transport Services (LPTS) network
stack due to improper handling of flow base entries, in which too many
known entries for a protocol can be created, resulting in dropping
existing or new sessions. An unauthenticated, remote attacker can
exploit this to cause an exhaustion of resources by sending continuous
connection attempts to open TCP ports.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160519-ios-xr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?711e9420");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux95576");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux95576");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# check model
model = get_kb_item("CISCO/model");
if (model)
{
  if (model !~ "ciscoASR9[0-9]{3}([^0-9]|$)") audit(AUDIT_DEVICE_NOT_VULN, model);
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_DEVICE_NOT_VULN, model);
}

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
flag = FALSE;
fix = "6.1.1";

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

# Version check
if ( ver_compare(ver:version, fix:fix, strict:FALSE) < 0) flag = TRUE;

if (flag)
{
  report =
    '\n  Cisco bug ID      : CSCux95576' +
    '\n  Installed release : ' + version;

  report += '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XR", version);
