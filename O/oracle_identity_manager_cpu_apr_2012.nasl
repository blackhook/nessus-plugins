#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72415);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-0532");
  script_bugtraq_id(53060);

  script_name(english:"Oracle Identity Manager (April 2012 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an identity management application installed that
is affected by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the April 2012 Critical Patch Update for
Oracle Identity Manager. It is, therefore, affected by an unspecified
vulnerability related to User Config Management.");
  # https://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83822adc");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2012 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 Tenable Network Security, Inc.");

  script_dependencies("oracle_identity_management_installed.nbin");
  script_require_keys("installed_sw/Oracle Identity Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("Oracle/OIM/Installed");
installs = get_kb_list_or_exit("Oracle/OIM/*/Version");

product = "Oracle Identity Manager";
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

fixed = NULL;

if (version =~ "^11\.1\.1\.3(\.|$)")
  fixed = "11.1.1.3.8";
else if (version =~ "^11\.1\.1\.5(\.|$)")
  fixed = "11.1.1.5.2";

if (!isnull(fixed))
{
  if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed +
        '\n';
      security_warning(extra:report, port:0);
    }
    else security_warning(0);
    exit(0);
  }
}

audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);
