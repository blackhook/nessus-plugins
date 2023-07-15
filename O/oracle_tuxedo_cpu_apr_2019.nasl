#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124171);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-0734", "CVE-2018-0735", "CVE-2018-5407");
  script_bugtraq_id(105750, 105758, 105897);
  script_xref(name:"IAVA", value:"2019-A-0128");

  script_name(english:"Oracle Tuxedo Multiple Vulnerabilities (Apr 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Tuxedo installed on the remote host is missing
a security patch. It is, therefore, affected by multiple
vulnerabilities:
  
  - An information disclosure vulnerability exists in OpenSSL 
    due to the potential for a side-channel timing attack. 
    An unauthenticated attacker can exploit this to disclose 
    potentially sensitive information. 
    (CVE-2018-0734, CVE-2018-0735, CVE-2018-5407)");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9166970d");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2019 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0734");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:tuxedo");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_tuxedo_installed.nbin");
  script_require_keys("installed_sw/Oracle Tuxedo");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('oracle_rdbms_cpu_func.inc');
include('misc_func.inc');
include('install_func.inc');

app_name = 'Oracle Tuxedo';
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
rp = install['RP'];
path = install['path'];
rp_fix = 99;

if (version !~ "^12\.1\.1\.0($|\.|_)") 
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version + ' RP ' + rp, path);

if (rp == UNKNOWN_VER || rp < rp_fix)
{
  items = make_array('Path', path,
                     'Version', version,
                     'RP', rp,
                     'Required RP', rp_fix
                    );
  order = make_list('Path', 'Version', 'RP', 'Required RP');
  report = report_items_str(report_items:items, ordered_fields:order);
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version + ' RP ' + rp, path);
