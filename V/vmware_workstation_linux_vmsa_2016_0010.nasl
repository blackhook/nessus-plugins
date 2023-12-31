#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92946);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/21");

  script_cve_id("CVE-2016-5330");
  script_bugtraq_id(92323);
  script_xref(name:"VMSA", value:"2016-0010");

  script_name(english:"VMware Workstation 12.1.x < 12.1.1 Shared Folders (HGFS) Guest DLL Hijacking Arbitrary Code Execution (VMSA-2016-0010) (Linux)");
  script_summary(english:"Checks VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected
by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is
12.1.x prior to 12.1.1. It is, therefore, affected by an arbitrary
code execution vulnerability in the Shared Folders (HGFS) feature due
to improper loading of Dynamic-link library (DLL) files from insecure
paths, including the current working directory, which may not be under
user control. A remote attacker can exploit this vulnerability, by
placing a malicious DLL in the path or by convincing a user into
opening a file on a network share, to inject and execute arbitrary
code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0010.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation 12.1.1 or later.

Note that VMware Tools on Windows-based guests that use the Shared
Folders (HGFS) feature must also be updated to completely mitigate the
vulnerability.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5330");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'DLL Side Loading Vulnerability in VMware Host Guest Client Redirector');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_linux_installed.nbin");
  script_require_keys("Host/VMware Workstation/Version");
  script_exclude_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

version = get_kb_item_or_exit("Host/VMware Workstation/Version");

fix = '';
if (version =~ "^12\.1\.") fix = '12.1.1';

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Workstation", version);
