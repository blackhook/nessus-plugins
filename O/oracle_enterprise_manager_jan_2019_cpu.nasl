#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121225);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-4000",
    "CVE-2018-0732",
    "CVE-2018-0737",
    "CVE-2018-3303"
  );
  script_bugtraq_id(
    103766,
    104442,
    105647,
    106618
  );
  script_xref(name:"IAVA", value:"2020-A-0017");

  script_name(english:"Oracle Enterprise Manager Cloud Control (January 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by remote code execution and denial of service attacks.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Cloud Control installed on
the remote host is affected by multiple vulnerabilities in
Enterprise Manager Base Platform component:

  - A remote code execution vulnerability exists in Jython
    before 2.7.1rc1.
    An unauthenticated, remote attacker can exploit this by
    sending a serialized function to the deserializer.
    (CVE-2016-4000)

  - A denial of service (DoS) vulnerability exists in OpenSSL due to
    the client spending long periods of time generating
    a key from large prime values. A malicious remote server can
    exploit this issue via sending a very large prime value
    to the clients, resulting in a hang until the client has
    finished generating the key.
    (CVE-2018-0732)");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?799b2d05");
  # https://support.oracle.com/rs?type=doc&id=2466391.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2407cfcd");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2019
Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4000");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/17");

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
  patchid = '28970523';
  fix = '13.3.0.0.190115';
}
else if (version =~ '^13\\.2\\.0\\.0(\\.[0-9]+)?$')
{
  patchid = '28970534';
  fix = '13.2.0.0.190115';
}
else if (version =~ '^12\\.1\\.0\\.5(\\.[0-9]+)?$')
{
  patchid = '28970508';
  fix = '12.1.0.5.190115';
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

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
