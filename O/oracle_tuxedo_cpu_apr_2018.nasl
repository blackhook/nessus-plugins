#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136066);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-3736");
  script_bugtraq_id(101666);
  script_xref(name:"IAVA", value:"2018-A-0118-S");

  script_name(english:"Oracle Tuxedo Information Disclosure (Apr 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Tuxedo installed on the remote host is missing a security patch. It is, therefore, affected by an
information disclosure vulnerability due to a carry propagating bug in the x86_64 Montgomery squaring procedure in
OpenSSL before 1.0.2m and 1.1.0 before 1.1.0g. An unauthenticated, remote attacker can exploit this to disclose
potentially sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2018.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2018 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:tuxedo");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_tuxedo_installed.nbin", "oracle_tuxedo_local_nix_installed.nbin");
  script_require_keys("installed_sw/Oracle Tuxedo");

  exit(0);
}

include('install_func.inc');

app_name = 'Oracle Tuxedo';
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
rp = install['RP'];
path = install['path'];

rp_fix = 0;

if (version =~ "^12\.1\.1\.0($|\.|_)")
  rp_fix = 94;
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version + " RP " + rp, path);

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
