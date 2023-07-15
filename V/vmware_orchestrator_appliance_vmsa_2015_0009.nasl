#TRUSTED 7ad5b9e2ff8b277af2a20068a8cfb8bde8a6f9ae58de195d4e3d9f61d45d3998a1476b3368d628cd2f93e6be1d9cc26d4f2a582a30e3322b15341d7ceb7858869aa4584d21d4ae9429ba95667300aefc5480704e01e525c745033ec377381e0bf7ccbdf2e3acc14c678d7dc99f310340046144859145d257872dd189b3e8f30b304cb6fa6cb809f8dcea8d1ae2be03b590149b0464b9112cd1effe6a0f6a3b917a0f1f0304cfad9e5aefc6866eb00de9f1c2b3e44e1733abb8a2f3a4cbaad82cc8987bcc20cad38063653b0d4a285810e2a9176d539fc18ada4f24ff02cb626edee4a1de4b3c72b911b2423d98818f35df9b4e7a73c83091935f4788260d55adcbe8d041bc7f83eeac22406bc83fc2740ea5053ea0e01c3a2a7b1b62da4f5201e4a5de91a3b6cecad75dccf148fc44a47a35b16c298bad0f9f3ed9f3885282ebe3b9a9fe33026df9b9a10136eb63fc17c2d74ae8fdd507eb99b4b754be3016d77b1dad957e502de50378e4c8ca84a4f5155b9bc20e2b2a0979021ae751d7922c000c3559bdc430fca9fcf1da9d182a5a65fae8f0d91c391bc453a311fd1cf83be6a65ea5ad98ca975194b908a1ad99422de8d9b9a6fe05e26f61c21b091fa484dc1c73b4a5e5b49eb401399348c75f783d4016492dfe25edde0f576917251c4f92e8766d1429999eda5dc18e0496ec229623356d258dd5f524c97eca3d80401f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87762);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2015-6934");
  script_bugtraq_id(79648);
  script_xref(name:"VMSA", value:"2015-0009");
  script_xref(name:"IAVB", value:"2016-B-0006");
  script_xref(name:"CERT", value:"576313");

  script_name(english:"VMware vCenter / vRealize Orchestrator Appliance 4.2.x / 5.x / 6.x Java Object Deserialization RCE (VMSA-2015-0009)");
  script_summary(english:"Checks the version of VMware vCenter/vRealize Orchestrator Appliance.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter / vRealize Orchestrator Appliance
installed on the remote host is 4.2.x or 5.x or 6.x and includes the
Apache Commons Collections (ACC) library version 3.2.1. It is,
therefore, affected by a remote code execution vulnerability due to
unsafe deserialize calls of unauthenticated Java objects to the ACC
library. An unauthenticated, remote attacker can exploit this, by
sending a crafted request, to execute arbitrary code on the target
host.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0009.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/selfservice/microsites/search.do?cmd=displayKC&externalId=2141244");
  # https://blogs.apache.org/foundation/entry/apache_commons_statement_to_widespread
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91868e8b");
  # https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6d83db");
  script_set_attribute(attribute:"see_also", value:"https://www.infoq.com/news/2015/11/commons-exploit");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in VMware KB 2141244.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6934");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_orchestrator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_orchestrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vCenter Orchestrator/Version", "Host/VMware vCenter Orchestrator/VerUI", "Host/VMware vCenter Orchestrator/Build", "HostLevelChecks/proto", "Host/local_checks_enabled");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

version = get_kb_item_or_exit("Host/VMware vCenter Orchestrator/Version");
verui = get_kb_item_or_exit("Host/VMware vCenter Orchestrator/VerUI");

proto = get_kb_item_or_exit('HostLevelChecks/proto');
get_kb_item_or_exit("Host/local_checks_enabled");

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else
  exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

app_name = "VMware vCenter/vRealize Orchestrator Appliance";

if (version !~ "^4\.2($|\.)" && version !~ "^5\." && version !~ "^6\.")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, verui);

# if any of these files exist, we are vulnerable
# /var/lib/vco/app-server/deploy/vco/WEB-INF/lib/commons-collections-3.2.1.jar
# /var/lib/vco/configuration/lib/o11n/commons-collections-3.2.1.jar
# /opt/vmo/app-server/server/vmo/lib/commons-collections.jar
# /opt/vmo/configuration/jetty/lib/ext/commons-collections.jar

file1 = "/var/lib/vco/app-server/deploy/vco/WEB-INF/lib/commons-collections-3.2.1.jar";
file2 = "/var/lib/vco/configuration/lib/o11n/commons-collections-3.2.1.jar";
file3 = "/opt/vmo/app-server/server/vmo/lib/commons-collections.jar";
file4 = "/opt/vmo/configuration/jetty/lib/ext/commons-collections.jar";

file1_exists = info_send_cmd(cmd:"ls " + file1 + " 2>/dev/null");
file2_exists = info_send_cmd(cmd:"ls " + file2 + " 2>/dev/null");
file3_exists = info_send_cmd(cmd:"ls " + file3 + " 2>/dev/null");
file4_exists = info_send_cmd(cmd:"ls " + file4 + " 2>/dev/null");

if(info_t == INFO_SSH) ssh_close_connection();

if (empty_or_null(file1_exists) && empty_or_null(file2_exists) && empty_or_null(file3_exists) && empty_or_null(file4_exists))
  audit(AUDIT_INST_VER_NOT_VULN, app_name, verui);

report = '\n  Installed version  : ' + verui;
if (!empty_or_null(file1_exists))
  report += '\n  Vulnerable library : ' + file1;
if (!empty_or_null(file2_exists))
  report += '\n  Vulnerable library : ' + file2;
if (!empty_or_null(file3_exists))
  report += '\n  Vulnerable library : ' + file3;
if (!empty_or_null(file4_exists))
  report += '\n  Vulnerable library : ' + file4;
report +=  '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
