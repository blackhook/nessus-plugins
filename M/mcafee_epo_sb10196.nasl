#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100572);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3980");
  script_bugtraq_id(98559);
  script_xref(name:"MCAFEE-SB", value:"SB10196");

  script_name(english:"McAfee ePolicy Orchestrator 5.1.x < 5.1.3 HF1193124 / 5.3.x < 5.3.1 HF1194398 / 5.3.2 < 5.3.2 HF1193123 / 5.9.x < 5.9.0 HF1193951 Path Traversal RCE (SB10196)");
  script_summary(english:"Checks the version of ePolicy Orchestrator.");

  script_set_attribute(attribute:"synopsis", value:
"A security management application installed on the remote Windows
host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee ePolicy Orchestrator (ePO) installed on the
remote Windows host is 5.1.x prior to 5.1.3 hotfix 1193124, 5.3.x
prior to 5.3.1 hotfix 1194398, 5.3.2 prior to 5.3.2 hotfix 1193123, or
5.9.x prior to 5.9.0 hotfix 1193951. It is affected by a remote
command execution vulnerability due to improper sanitization of
user-supplied input. An authenticated, remote attacker can exploit
this, via a specially crafted request that uses directory traversal,
to execute arbitrary commands.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10196");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ePO version 5.1.3 hotfix 1193124 / 5.3.1 hotfix
1194398 / 5.3.2 hotfix 1193123 / 5.9.0 hotfix 1193951 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");
include("bsal.inc");
include("byte_func.inc");
include("zip.inc");

app_name = "McAfee ePO";
install = get_single_install(
  app_name : app_name,
  exit_if_unknown_ver : TRUE
);
dir = install['path'];
build_ver = install['version'];
report = NULL;

# We need the build numbers to construct the Hotfix path later
# to prevent it from auditing out during the RepositoryMgmt.jar version
# check:
# https://kc.mcafee.com/corporate/index?page=content&id=KB61057
if(build_ver =~ "^5\.1\.0\..*$")
{
  hf_jar_fix_ver = '5.1.3.278';
  req_build_ver = '5.1.0.509';
  hf_report = 'Upgrade to ePO 5.1.3 and then apply hotfix EPO513HF1193124.zip.';
}
else if(build_ver =~ "^5\.1\.1\..*$")
{
  hf_jar_fix_ver = '5.1.3.278';
  req_build_ver = '5.1.1.357';
  hf_report = 'Upgrade to ePO 5.1.3 and then apply hotfix EPO513HF1193124.zip.';
}
else if(build_ver =~ "^5\.1\.2\..*$")
{
  hf_jar_fix_ver = '5.1.3.278';
  req_build_ver = '5.1.2.348';
  hf_report = 'Upgrade to ePO 5.1.3 and then apply hotfix EPO513HF1193124.zip.';
}
else if(build_ver =~ "^5\.1\.3\..*$")
{
  hf_jar_fix_ver = '5.1.3.278';
  req_build_ver = '5.1.3.188';
  hf_report = 'Apply hotfix EPO513HF1193124.zip.';
}
else if(build_ver =~ "^5\.3\.0\..*$")
{
  hf_jar_fix_ver = '5.3.1.285';
  req_build_ver = '5.3.0.400';
  hf_report = 'Upgrade to ePO 5.3.1 and then apply hotfix EPO531HF1194398.zip.';
}
else if(build_ver =~ "^5\.3\.1\..*$")
{
  hf_jar_fix_ver = '5.3.1.285';
  req_build_ver = '5.3.1.188';
  hf_report = 'Apply hotfix EPO531HF1194398.zip.';
}
else if(build_ver =~ "^5\.3\.2\..*$")
{
  hf_jar_fix_ver = '5.3.2.282';
  req_build_ver = '5.3.2.156';
  hf_report = 'Apply hotfix EPO532HF1193123.zip.';
}
else if(build_ver =~ "^5\.9\.0\..*$")
{
  hf_jar_fix_ver = '5.9.0.823';
  req_build_ver = '5.9.0.732';
  hf_report = 'Apply hotfix EPO590HF1193951.zip.';
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, build_ver, dir);

# Based on the required build number version, extract the "Specification-Version"
# from the RepositoryMgmt.jar file's META-INF\MANIFEST.MF if it exists.

# Get one of the modified JAR files.
hf_jar_path = "\server\extensions\installed\RepositoryMgmt\" + req_build_ver + "\webapp\WEB-INF\lib\RepositoryMgmt.jar";
jar_path = hotfix_append_path(path:dir, value:hf_jar_path);
jar_contents = hotfix_get_file_contents(jar_path);
hotfix_handle_error(error_code:jar_contents['error'], file:jar_path, exit_on_fail:TRUE);
hotfix_check_fversion_end();

# Get the version from the manifest.
manifest = zip_parse(blob:jar_contents['data'], "META-INF/MANIFEST.MF");
match = pregmatch(string:manifest, pattern:"Specification-Version: ((\d+\.?)+)");
if (isnull(match)) exit(1, "Failed to parse specification version from manifest.");
jar_ver = match[1];

port = kb_smb_transport();

# Compare RepositoryMgmt.jar's reported file version to the version the patches replace.
if(ver_compare(ver:jar_ver, fix:hf_jar_fix_ver, strict:FALSE) < 0)
{
  report =
    '\n Application : McAfee ePolicy Orchestrator ' + build_ver +
    '\n Path        : ' + jar_path +
    '\n Version     : ' + jar_ver +
    '\n Fix version : ' + hf_jar_fix_ver +
    '\n Fix         : ' + hf_report +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name + "'s RepositoryMgmt.jar", jar_ver);
