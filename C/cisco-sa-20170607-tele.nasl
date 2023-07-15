#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100838);
  script_version("1.4");
  script_cvs_date("Date: 2019/07/12 12:39:16");

  script_cve_id("CVE-2017-6648");
  script_bugtraq_id(98934);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux94002");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170607-tele");

  script_name(english:"Cisco TelePresence Endpoint SIP INVITE Packet Flood DoS (cisco-sa-20170607-tele)");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"A video conferencing application running on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host either is running Cisco TelePresence Codec (TC) that
is version 7.2.x prior to 7.3.8 or is running Cisco Collaboration
Endpoint (CE) software that is version 8.x prior 8.3.0. It is,
therefore, affected by a denial of service vulnerability in the
Session Initiation Protocol (SIP) due to a lack of proper flow-control
mechanisms within the software. An unauthenticated, remote attacker
can exploit this, by sending a flood of SIP INVITE packets, to cause
the TelePresence endpoint to reload unexpectedly.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-tele
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7585d75f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux94002");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco TelePresence Codec (TC) version 7.3.8 or Cisco
Collaboration Endpoint (CE) version 8.3.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_tc_software");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:telepresence_ce_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Cisco TelePresence TC/CE software";
device = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");
flag=FALSE;

if (
  device !~ " C[2469]0($|[ \n\r])" &&
  device !~ " EX[69]0($|[ \n\r])" &&
  device !~ " MX[2378]00(\sG2)?($|[ \n\r])" &&
  device !~ " Profile.+($|[ \n\r])" &&
  device !~ " SX[128]0($|[ \n\r])" &&
  device !~ " DX[78]0($|[ \n\r])"
) audit(AUDIT_HOST_NOT, "an affected Cisco TelePresence device");

short_version = pregmatch(pattern: "^(TC|ce)(\d+(?:\.\d+){0,2})", string:version);
if (isnull(short_version))
  audit(AUDIT_NOT_DETECT, app_name);
else
{
  short_type = short_version[1];
  short_num = short_version[2];
}

if(short_type == "TC"){
  if (short_num =~ "^7(\.3)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);
  if (short_num =~ "^7\.[23]" && ver_compare(ver:short_num, fix:'7.3.8', strict:FALSE) < 0)
    flag = TRUE;
}
else if (short_type == "ce"){
  if (short_num =~ "^8\." && ver_compare(ver:short_num, fix:'8.3.0', strict:FALSE) < 0)
    flag = TRUE;
}
else audit(AUDIT_NOT_DETECT, app_name);

if (flag)
{
  port = 0;
  report = '\n  Detected version : ' + version +
           '\n  Fixed version    : See solution.' +
           '\n  Cisco bug ID     : CSCux94002' +
           '\n';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
