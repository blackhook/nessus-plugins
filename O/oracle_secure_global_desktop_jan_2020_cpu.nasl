#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133042);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-0227",
    "CVE-2019-1547",
    "CVE-2019-1552",
    "CVE-2019-1563",
    "CVE-2019-10092",
    "CVE-2019-10098",
    "CVE-2019-17091"
  );
  script_bugtraq_id(107867);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Secure Global Desktop Multiple Vulnerabilities (January 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Secure Global Desktop installed on the remote host is missing a security patch from the January
2020 Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability exists in the Core (Apache Axis) component. An unauthenticated, 
    adjacent attacker can exploit this issue, to execute arbitrary commands. (CVE-2019-0227)

  - A cross-site scripting vulnerability exists in the Web Server (Appache HTTPD Server) component. An
    unauthenticated, remote attacker can exploit this issue via causing the link on the mod_proxy error page
    to be malformed and point to a page of the attacker's choice. (CVE-2019-10092)

  - A cross-site scripting vulnerability exists in faces/context/PartialViewContextImpl.java in Eclipse
    (Mojarra) due to mishandling of a client window field. An unauthenticated, remote attacker can exploit
    this issue, to perform unauthorized update, insert or delete access to some of Oracle Communications
    Unified Inventory Management accessible data as well as to perform an unauthorized read access to a subset
    of Oracle Communications Unified Inventory Management accessible data. (CVE-2019-17091)");
  # https://www.oracle.com/security-alerts/cpujan2020.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc4414d8");
  # https://www.oracle.com/security-alerts/cpujan2020verbose.html#OVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cb6a420");
  script_set_attribute(attribute:"solution", value:
"Apply the appropiate patch according to the January 2020 Oracle Critical Patch Update Advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10098");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-0227");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_secure_global_desktop_installed.nbin");
  script_require_keys("Host/Oracle_Secure_Global_Desktop/Version");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

app = 'Oracle Secure Global Desktop';
version = get_kb_item_or_exit('Host/Oracle_Secure_Global_Desktop/Version');

# this check is for Oracle Secure Global Desktop packages built for Linux platform
uname = get_kb_item_or_exit('Host/uname');
if ('Linux' >!< uname) audit(AUDIT_OS_NOT, 'Linux');

fix_required = NULL;

if (version =~ "^5\.40($|\.)") fix_required = 'Patch_54p6';

if (isnull(fix_required)) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle Secure Global Desktop', version);

patches = get_kb_list('Host/Oracle_Secure_Global_Desktop/Patches');

patched = FALSE;
foreach patch (patches)
{
  if (patch == fix_required)
  {
    patched = TRUE;
    break;
  }
}

if (patched) audit(AUDIT_INST_VER_NOT_VULN, app, version + ' (with ' + fix_required + ')');

report = '\n  Installed version : ' + version +
         '\n  Patch required    : ' + fix_required +
         '\n';
security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
