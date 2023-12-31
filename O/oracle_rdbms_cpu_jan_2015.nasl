#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80906);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2014-6514",
    "CVE-2014-6541",
    "CVE-2014-6567",
    "CVE-2014-6577",
    "CVE-2014-6578",
    "CVE-2015-0370",
    "CVE-2015-0371",
    "CVE-2015-0373"
  );
  script_bugtraq_id(
    72134,
    72139,
    72145,
    72149,
    72158,
    72163,
    72166,
    72171
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2015 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the January 2015 Critical
Patch Update (CPU). It is, therefore, affected by security issues in
the following components :

  - Core RDBMS
  - DBMS_UTILITY
  - PL/SQL
  - Recovery
  - Workspace Manager
  - XML Developer's Kit for C");
  # https://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75c6cafb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2015 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

################################################################################
# JAN2015
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.22", "CPU", "19854433, 19769499");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.59", "CPU", "20126914");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.59", "CPU", "20126915");
# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.2", "CPU", "19769480");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.1", "CPU", "19720843");
# RDBMS 12.1.0.1
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.6", "CPU", "19769486");
patches["12.1.0.1"]["db"]["win"] = make_array("patch_level", "12.1.0.1.16", "CPU", "20160748");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.13", "CPU", "19854461, 19769496");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.36", "CPU", "20233167");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.36", "CPU", "20233168");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.5", "CPU", "19854503, 19769489");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.12", "CPU", "20127071");
# JVM 11.2.0.3
patches["11.2.0.3"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.3.2", "CPU", "19877443");
patches["11.2.0.3"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.3.2", "CPU", "20227195");
# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.2", "CPU", "19877336");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.1", "CPU", "20225938");
# JVM 11.1.0.7
patches["11.1.0.7"]["ojvm"]["nix"] = make_array("patch_level", "11.1.0.7.2", "CPU", "19877446");
patches["11.1.0.7"]["ojvm"]["win"] = make_array("patch_level", "11.1.0.7.2", "CPU", "20227146");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.2", "CPU", "19877440");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.2", "CPU", "20225982");
# JVM 12.1.0.1
patches["12.1.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.1.2", "CPU", "19877342");
patches["12.1.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.1.2", "CPU", "20225916");

check_oracle_database(patches:patches, high_risk:TRUE);
