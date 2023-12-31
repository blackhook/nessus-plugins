#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56064);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2009-0972",
    "CVE-2009-0973",
    "CVE-2009-0975",
    "CVE-2009-0976",
    "CVE-2009-0977",
    "CVE-2009-0978",
    "CVE-2009-0979",
    "CVE-2009-0980",
    "CVE-2009-0981",
    "CVE-2009-0984",
    "CVE-2009-0985",
    "CVE-2009-0986",
    "CVE-2009-0988",
    "CVE-2009-0991",
    "CVE-2009-0992",
    "CVE-2009-0997"
  );
  script_bugtraq_id(34461);

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2009 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the April 2009 Critical
Patch Update (CPU) and therefore is potentially affected by security
issues in the following components :

  - Advanced Queuing

  - Application Express

  - Cluster Ready Services

  - Core RDBMS

  - Database Vault

  - Listener

  - Password Policy

  - Resource Manager

  - SQLX Functions

  - Workspace Manager");
  # https://www.oracle.com/technetwork/topics/security/cpuapr2009-099563.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3c49435");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2009 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/15");
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
# APR2009
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.0.1", "CPU", "8290478");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.1", "CPU", "8343061");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.1", "CPU", "8343070");
# RDBMS 11.1.0.6
patches["11.1.0.6"]["db"]["nix"] = make_array("patch_level", "11.1.0.6.6", "CPU", "8290402");
patches["11.1.0.6"]["db"]["win32"] = make_array("patch_level", "11.1.0.6.9", "CPU", "8333655");
patches["11.1.0.6"]["db"]["win64"] = make_array("patch_level", "11.1.0.6.9", "CPU", "8333657");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.14", "CPU", "8290534");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.32", "CPU", "8300356");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.0.4", "CPU", "8290506");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.18", "CPU", "8307237");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.18", "CPU", "8307238");

check_oracle_database(patches:patches, high_risk:TRUE);
