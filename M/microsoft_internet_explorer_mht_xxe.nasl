#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(125154);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/15 17:15:05");

  script_name(english:"Internet Explorer .mht XML External Entity Vulnerability");
  script_summary(english:"Checks the version of Microsoft Internet Explorer.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by an XXE vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is affected 
by an XML External Entity attack which could lead to an information
disclosure. An attacker would need to host a malicious file that is 
designed to exploit the vulnerability and then convince a user to 
download the malicious file and then open the file in Internet 
Explorer.");
  # http://hyp3rlinx.altervista.org/advisories/MICROSOFT-INTERNET-EXPLORER-v11-XML-EXTERNAL-ENTITY-INJECTION-0DAY.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2b9f0b4");
  script_set_attribute(attribute:"solution", value:
"No fix currently exists. Contact the vendor for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on an analysis of the vulnerability by Tenable.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/IE/Version", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

arch = get_kb_item_or_exit("SMB/ARCH");
path = NULL;
path_wow = NULL;
version = get_kb_item_or_exit("SMB/IE/Version");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

# Try to get App Paths. If not, defer to program files/Internet Explorer
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE\";
path = get_registry_value(handle:hklm, item:key);

if(isnull(path))
{
  path = hotfix_get_programfilesdir();
  path = hotfix_append_path(path:path, value:"Internet Explorer\iexplore.exe");
}

if(arch == "x64")
{

  key_wow = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE\";
  path_wow = get_registry_value(handle:hklm, item:key);

  if(isnull(path_wow))
  {
    path_wow = hotfix_get_programfilesdirx86();
    path_wow = hotfix_append_path(path:path, value:"Internet Explorer\iexplore.exe");
  }
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if(!isnull(path))
  ie_exists = hotfix_file_exists(path:path);
if(!isnull(path_wow))
  ie_exists_wow = hotfix_file_exists(path:path_wow);

hotfix_check_fversion_end();

if(ie_exists || ie_exists_wow)
{

  report =
  '\n  Installed Version : ' + version + 
  '\n  Fix               : No fix currently exists.' +
  '\n';

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);

}
else audit(AUDIT_HOST_NOT, "affected");

