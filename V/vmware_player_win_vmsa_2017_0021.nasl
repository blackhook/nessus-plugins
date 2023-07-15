#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105555);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2017-4933",
    "CVE-2017-4941",
    "CVE-2017-5715",
    "CVE-2017-5753"
  );
  script_bugtraq_id(
    102238,
    102240,
    102371,
    102376
  );
  script_xref(name:"VMSA", value:"2017-0021");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"VMSA", value:"2018-0002");

  script_name(english:"VMware Player 12.x < 12.5.8 Multiple Vulnerabilities (VMSA-2017-0021) (VMSA-2018-0002) (Spectre)");
  script_summary(english:"Checks the VMware Player version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Player installed on the remote Windows host
is 12.x prior to 12.5.8. It is, therefore, affected by multiple
vulnerabilities that can allow code execution in a virtual machine
via the authenticated VNC session as well as cause information disclosure from one
virtual machine to another virtual machine on the same host.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0021.html");
  script_set_attribute(attribute:"see_also", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0368");
  script_set_attribute(attribute:"see_also", value:"https://www.talosintelligence.com/vulnerability_reports/TALOS-2017-0369");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/us/security/advisories/VMSA-2018-0002.html");
  script_set_attribute(attribute:"see_also", value:"https://meltdownattack.com/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Player version 12.5.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4941");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_player_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Player");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

install = get_single_install(app_name:"VMware Player", exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

fix = '';
if (version =~ "^12\.") fix = '12.5.8';

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Player", version, path);
