#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124157);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-0734",
    "CVE-2018-0735",
    "CVE-2018-1257",
    "CVE-2018-1258",
    "CVE-2018-1656",
    "CVE-2018-5407",
    "CVE-2018-11039",
    "CVE-2018-11040",
    "CVE-2018-12539",
    "CVE-2018-15756"
  );
  script_bugtraq_id(
    104222,
    104260,
    105118,
    105126,
    105703,
    105750,
    105758,
    105897
  );
  script_xref(name:"IAVA", value:"2019-A-0130");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Apr 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple vulnerabilities in
Enterprise Manager Base Platform component:

  - Networking component of Enterprise Manager Base Platform (Spring Framework)
  is easily exploited and may allow an unauthenticated, remote attacker to takeover
  the Enterprise Manager Base Platform.
  (CVE-2018-1258, CVE-2018-11039, CVE-2018-11040, CVE-2018-1257, CVE-2018-15756)

  - Agent Next Gen (IBM Java) vulnerability allows unauthenticated, remote attacker
  unauthorized access to critical data or complete access to all Enterprise Manager
  Base Platform accessible data. (CVE-2018-1656, CVE-2018-12539)

  - An information disclosure vulnerability exists in OpenSSL due to the potential
  for a side-channel timing attack. An unauthenticated attacker can exploit
  this to disclose potentially sensitive information. 
  (CVE-2018-0734, CVE-2018-0735, CVE-2018-5407)");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9166970d");
  # https://support.oracle.com/rs?type=doc&id=2498664.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba7181fa");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2019
Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1258");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('oracle_rdbms_cpu_func.inc');
include('install_func.inc');

product = 'Oracle Enterprise Manager Cloud Control';
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);
version = install['version'];
emchome = install['path'];

patchid = NULL;
missing = NULL;
patched = FALSE;
fix = NULL;

if (version =~ '^13\\.3\\.0\\.0(\\.[0-9]+)?$')
{
  patchid = '29433931';
  fix = '13.3.0.0.190416';
}
else if (version =~ '^13\\.2\\.0\\.0(\\.[0-9]+)?$')
{
  patchid = '29433916';
  fix = '13.2.0.0.190416';
}
else if (version =~ '^12\\.1\\.0\\.5(\\.[0-9]+)?$')
{
  patchid = '29433895';
  fix = '12.1.0.5.190416';
}

if (isnull(patchid))
  audit(AUDIT_HOST_NOT, 'affected');

# compare version to check if we've already adjusted for patch level during detection
if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, product, version, emchome);

# Now look for the affected components
patchesinstalled = find_patches_in_ohomes(ohomes:make_list(emchome));
if (isnull(patchesinstalled))
  missing = patchid;
else
{
  foreach applied (keys(patchesinstalled[emchome]))
  {
    if (applied == patchid)
    {
      patched = TRUE;
      break;
    }
    else
    {
      foreach bugid (patchesinstalled[emchome][applied]['bugs'])
      {
        if (bugid == patchid)
        {
          patched = TRUE;
          break;
        }
      }
      if (patched) break;
    }
  }
  if (!patched)
    missing = patchid;
}

if (empty_or_null(missing))
  audit(AUDIT_HOST_NOT, 'affected');

order = make_list('Product', 'Version', 'Missing patch');
report = make_array(
  order[0], product,
  order[1], version,
  order[2], patchid
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
