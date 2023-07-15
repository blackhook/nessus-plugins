#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133055);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/01");

  script_cve_id(
    "CVE-2020-2608",
    "CVE-2020-2610",
    "CVE-2020-2611",
    "CVE-2020-2612",
    "CVE-2020-2613",
    "CVE-2020-2615",
    "CVE-2020-2616",
    "CVE-2020-2617",
    "CVE-2020-2618",
    "CVE-2020-2619",
    "CVE-2020-2620",
    "CVE-2020-2621",
    "CVE-2020-2622",
    "CVE-2020-2623",
    "CVE-2020-2624",
    "CVE-2020-2625",
    "CVE-2020-2626",
    "CVE-2020-2628",
    "CVE-2020-2629",
    "CVE-2020-2630",
    "CVE-2020-2631",
    "CVE-2020-2632",
    "CVE-2020-2633",
    "CVE-2020-2634",
    "CVE-2020-2635",
    "CVE-2020-2636",
    "CVE-2020-2639",
    "CVE-2020-2642",
    "CVE-2020-2643",
    "CVE-2020-2644",
    "CVE-2020-2645"
  );
  script_xref(name:"IAVA", value:"2020-A-0017");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple vulnerabilities in
Enterprise Manager Base Platform component:

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager,
    Supported versions that are affected are 12.1.0.5, 13.2.0.0 and 13.3.0.0. Easily exploitable
    vulnerability allows high privileged attacker with network access via HTTP to compromise
    Enterprise Manager Base Platform. Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access to all Enterprise Manager Base
    Platform accessible data as well as unauthorized update, insert or delete access to some of
    Enterprise Manager Base Platform accessible data and unauthorized ability to cause a partial
    denial of service (partial DOS) of Enterprise Manager Base Platform.

    Following components of Enterprise Manager Base Platform product are vulnerable to above
    vulnerability:

      - Application Service Level Mgmt (CVE-2020-2631, CVE-2020-2636)
      - Connector Framework (CVE-2020-2624, CVE-2020-2633, CVE-2020-2642, CVE-2020-2645)
      - Enterprise Config Management (CVE-2020-2610, CVE-2020-2611, CVE-2020-2612, CVE-2020-2618,
                                      CVE-2020-2619, CVE-2020-2620, CVE-2020-2621)
      - Cloud Control Manager - OMS (CVE-2020-2626)
      - Configuration Standard Framewk (CVE-2020-2634)
      - Discovery Framework (CVE-2020-2617)
      - Enterprise Manager Repository (CVE-2020-2616)
      - Event Management (CVE-2020-2622)
      - Extensibility Framework (CVE-2020-2629, CVE-2020-2630)
      - Global EM Framework (CVE-2020-2613)
      - Host Management (CVE-2020-2628, CVE-2020-2639)
      - Job System (CVE-2020-2625, CVE-2020-2643)
      - Metrics Framework (CVE-2020-2623)
      - Oracle Management Service (CVE-2020-2615, CVE-2020-2644)
      - Repository (CVE-2020-2608)
      - System Monitoring (CVE-2020-2632, CVE-2020-2635)");
  # https://www.oracle.com/security-alerts/cpujan2020.html#AppendixEM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3df84e9");
  # https://www.oracle.com/security-alerts/cpujan2020verbose.html#EM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91e1354f");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Jan 2020
Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2645");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  patchid = '30592540';
  fix = '13.3.0.0.200114';
}
else if (version =~ '^13\\.2\\.0\\.0(\\.[0-9]+)?$')
{
  patchid = '30592558';
  fix = '13.2.0.0.200114';
}
else if (version =~ '^12\\.1\\.0\\.5(\\.[0-9]+)?$')
{
  patchid = '30592609';
  fix = '12.1.0.5.200114';
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
