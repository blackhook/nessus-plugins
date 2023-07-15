#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(100784);
 script_version("1.3");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVA", value:"0001-A-0634");

 script_name(english:"McAfee Antivirus Engine Out of Date");
 script_summary(english:"Checks that the remote host has the latest antivirus engine installed.");

 script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
using an out-of-date engine.");
 script_set_attribute(attribute:"description", value:
"McAfee VirusScan, an antivirus application, is installed on the remote
host. However, its antivirus engine is out of date and should be
upgraded.");
 script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2017-2020 Tenable Network Security, Inc.");

 script_dependencies("mcafee_installed.nasl");
 script_require_keys("Antivirus/McAfee/engine_updated", "Antivirus/McAfee/engine_report");
 script_require_ports(139, 445);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

updated = get_kb_item_or_exit("Antivirus/McAfee/engine_updated");
version= get_kb_item_or_exit("Antivirus/McAfee/engine_version");

if(updated)
  audit(AUDIT_INST_VER_NOT_VULN, "McAfee Antivirus Engine", version);

port = get_kb_item('SMB/transport');
if(!port) port = 445;


extra = get_kb_item_or_exit("Antivirus/McAfee/engine_report");

security_report_v4(severity:SECURITY_NOTE, port:port, extra:extra);
