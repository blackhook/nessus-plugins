#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86576);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-4794",
    "CVE-2015-4796",
    "CVE-2015-4857",
    "CVE-2015-4863",
    "CVE-2015-4873",
    "CVE-2015-4888",
    "CVE-2015-4900"
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2015 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2015 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities in the following components :

  - Core RDBMS (CVE-2015-4857)
  - Database Scheduler (CVE-2015-4873)
  - Java VM (CVE-2015-4794, CVE-2015-4796, CVE-2015-4888)
  - Portable Clusterware (CVE-2015-4863)
  - XDB-XML Database (CVE-2015-4900)");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/23");

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
# OCT2015
patches = make_nested_array();

# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.5", "CPU", "21359755");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.10", "CPU", "21821214");
# RDBMS 12.1.0.1 #
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.9", "CPU", "21352619");
patches["12.1.0.1"]["db"]["win"] = make_array("patch_level", "12.1.0.1.21", "CPU", "21744907");
# RDBMS 11.2.0.4 #
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.8", "CPU", "21352635, 21352646");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.20", "CPU", "21821802");

# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.5", "CPU", "21555660");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.4", "CPU", "21788394");
# JVM 12.1.0.1
patches["12.1.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.1.5", "CPU", "21555669");
patches["12.1.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.1.5", "CPU", "21788365");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.4", "CPU", "21555791");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.4", "CPU", "21788344");


check_oracle_database(patches:patches, high_risk:TRUE);
