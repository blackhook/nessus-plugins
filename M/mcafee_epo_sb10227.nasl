#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110813);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/22");

  script_cve_id("CVE-2017-3936");
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"MCAFEE-SB", value:"SB10227");

  script_name(english:"McAfee ePolicy Orchestrator CSV File Handling Arbitrary Command Execution (SB10227)");
  script_summary(english:"Checks the installed version of ePolicy Orchestrator.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by arbitrary command execution.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee ePolicy Orchestrator
that contains a flaw that is triggered as user-supplied input passed
via CSV files is not properly sanitized. This may allow a context-
dependent attacker to potentially execute arbitrary commands.");
  # https://kc.mcafee.com/resources/sites/MCAFEE/content/live/SECURITY_BULLETIN/10000/SB10227/en_US/SB10227_ePolicy%20Orchestrator_blind_command_injection_vulnerability_CVE-2017-3936.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cec3a9e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ePO 5.9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3936");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/29");

  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/mcafee_epo/Path", "SMB/mcafee_epo/ver");
  script_require_ports("SMB/transport", 139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

app_name = "McAfee ePolicy Orchestrator";
version = get_kb_item_or_exit("SMB/mcafee_epo/ver");
install_path = get_kb_item_or_exit("SMB/mcafee_epo/Path");

# Users of ePO 5.1.3 or earlier are recommended to upgrade to ePO 5.3.3 or 5.9.1.
# Users of ePO 5.3.2 or earlier are recommended to upgrade to ePO 5.3.3 or 5.9.1.
# Users of ePO 5.9.0 are recommended to upgrade to ePO 5.9.1.

fix = NULL;

if (version =~ "^5\.1\.[0-3]" || version =~ "^5\.3\.[0-2]") fix = "5.3.3";
else if (version == "5.9.0") fix = "5.9.1";
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = kb_smb_transport();
  report =
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);
