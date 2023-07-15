#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109733);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2018-2587", "CVE-2018-2739", "CVE-2018-2879");
  script_bugtraq_id(103784, 103788, 103822);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Access Manager Multiple Vulnerabilities (Apr 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a Single Sign On (SSO) application installed that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Access Manager installed on the remote host is
affected by multiple vulnerabilities.");
  # https://www.oracle.com/technetwork/topics/security/cpuapr2018-3678067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50aa8cea");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the April 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_access_manager_installed.nbin");
  script_require_keys("Oracle/OAM/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("Oracle/OAM/Installed");
installs = get_kb_list_or_exit("Oracle/OAM/*/Version");
product = "Oracle Access Manager";

path = branch(keys(installs));
report = NULL;

version = installs[path];
path = path - "Oracle/OAM/" - "/Version";

if (version =~ "^10\.1\.4\.3(\.|$)")
  fixed = "10.1.4.3.0.13"; # according to the info in the patch file: install_info
else if (version =~ "^11\.1\.2\.3(\.|$)")
  fixed = "11.1.2.3.180417";
else if (version =~ "^12\.2\.1\.3(\.|$)")
  fixed = "12.2.1.3.180414"; # the 14 aligns w/ the release notes
else
  audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);

if (ver_compare(ver:version, fix:fixed, strict:FALSE) >= 0) audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);

report =
   '\n  The following vulnerable version of ' + product + ' was found' +
   '\n  on the remote host : ' +
   '\n' +
   '\n  Path              : ' + path +
   '\n  Installed version : ' + version +
   '\n  Fixed version     : ' + fixed +
   '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
