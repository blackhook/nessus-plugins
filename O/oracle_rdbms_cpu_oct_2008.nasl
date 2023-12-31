#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56062);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2008-2624",
    "CVE-2008-2625",
    "CVE-2008-3976",
    "CVE-2008-3980",
    "CVE-2008-3982",
    "CVE-2008-3983",
    "CVE-2008-3984",
    "CVE-2008-3989",
    "CVE-2008-3990",
    "CVE-2008-3991",
    "CVE-2008-3992",
    "CVE-2008-3994",
    "CVE-2008-3995",
    "CVE-2008-3996",
    "CVE-2008-4005"
  );
  script_bugtraq_id(31683);

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2008 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2008
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Core RDBMS

  - Oracle Application Express

  - Oracle Data Capture

  - Oracle Data Mining

  - Oracle OLAP

  - Oracle Spatial

  - Upgrade

  - Workspace Manager");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2008-100299.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a813466");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2008 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

################################################################################
# OCT2008
patches = make_nested_array();

# RDBMS 11.1.0.6
patches["11.1.0.6"]["db"]["nix"] = make_array("patch_level", "11.1.0.6.4", "CPU", "7375639");
patches["11.1.0.6"]["db"]["win32"] = make_array("patch_level", "11.1.0.6.7", "CPU", "7378392");
patches["11.1.0.6"]["db"]["win64"] = make_array("patch_level", "11.1.0.6.7", "CPU", "7378393");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.12", "CPU", "7375686");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.28", "CPU", "7367493");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.0.2", "CPU", "7375644");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.9", "CPU", "7386320");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.9", "CPU", "7386321");
# RDBMS 10.2.0.3
patches["10.2.0.3"]["db"]["nix"] = make_array("patch_level", "10.2.0.3.8", "CPU", "7369190");
patches["10.2.0.3"]["db"]["win32"] = make_array("patch_level", "10.2.0.3.27", "CPU", "7353782");
patches["10.2.0.3"]["db"]["win64"] = make_array("patch_level", "10.2.0.3.27", "CPU", "7353785");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.11", "CPU", "7375660");

check_oracle_database(patches:patches);
