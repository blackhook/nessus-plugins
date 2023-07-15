#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45625);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2009-1996",
    "CVE-2009-3410",
    "CVE-2009-3411",
    "CVE-2009-3412",
    "CVE-2009-3413",
    "CVE-2009-3414",
    "CVE-2009-3415",
    "CVE-2010-0071",
    "CVE-2010-0072"
  );
  script_bugtraq_id(
    37728,
    37729,
    37730,
    37731,
    37733,
    37738,
    37740,
    37743,
    37745
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2010 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the January 2010
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Listener

  - Oracle OLAP

  - Application Express Application Builder

  - Oracle Data Pump

  - Oracle Spatial

  - Logical Standby

  - RDBMS

  - Oracle Spatial

  - Unzip");
  # https://www.oracle.com/technetwork/topics/security/cpujan2010-084891.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56a3eac7");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2010 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

################################################################################
# JAN2010
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.2", "CPU", "9114072, 9209238");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.4", "CPU", "9166858");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.4", "CPU", "9166861");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.17", "CPU", "9119261");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.37", "CPU", "9187104");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.3", "CPU", "9119226, 9119284");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.30", "CPU", "9169457");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.30", "CPU", "9169460");

check_oracle_database(patches:patches, high_risk:TRUE);
