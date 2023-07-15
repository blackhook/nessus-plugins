#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56057);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2007-3853",
    "CVE-2007-3854",
    "CVE-2007-3855",
    "CVE-2007-3856",
    "CVE-2007-3857",
    "CVE-2007-3858",
    "CVE-2007-3859"
  );
  script_bugtraq_id(24887);

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2007 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the July 2007
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Advanced Queuing

  - DataGuard

  - JavaVM

  - Oracle Data Mining

  - Oracle Text

  - PL/SQL

  - Rules Manager

  - Spatial

  - SQL Compiler");
  # https://www.oracle.com/technetwork/topics/security/cpujul2007-087014.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d303ce9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2007 Oracle Critical
Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-516");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/17");
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
# JUL2007
patches = make_nested_array();

# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.7", "CPU", "6079585");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.16", "CPU", "6115804");
# RDBMS 10.2.0.3
patches["10.2.0.3"]["db"]["nix"] = make_array("patch_level", "10.2.0.3.3", "CPU", "6079591");
patches["10.2.0.3"]["db"]["win32"] = make_array("patch_level", "10.2.0.3.8", "CPU", "6116131");
patches["10.2.0.3"]["db"]["win64"] = make_array("patch_level", "10.2.0.3.8", "CPU", "6116139");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.6", "CPU", "6079588");
patches["10.2.0.2"]["db"]["win32"] = make_array("patch_level", "10.2.0.2.8", "CPU", "6013105");
patches["10.2.0.2"]["db"]["win64"] = make_array("patch_level", "10.2.0.2.8", "CPU", "6013121");

check_oracle_database(patches:patches, high_risk:TRUE);
