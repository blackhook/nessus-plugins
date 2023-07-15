#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56060);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2008-1812",
    "CVE-2008-1813",
    "CVE-2008-1814",
    "CVE-2008-1815",
    "CVE-2008-1816",
    "CVE-2008-1817",
    "CVE-2008-1818",
    "CVE-2008-1819",
    "CVE-2008-1820",
    "CVE-2008-1821"
  );
  script_bugtraq_id(28725);

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2008 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the April 2008 Critical
Patch Update (CPU) and therefore is potentially affected by security
issues in the following components :

  - Advanced Queuing

  - Audit

  - Authentication

  - Change Data Capture

  - Core RDBMS

  - Data Pump

  - Export

  - Oracle Enterprise Manager

  - Oracle Net Services

  - Oracle Secure Enterprise Search or Ultra Search

  - Oracle Spatial

  - Query Optimizer");
  # https://www.oracle.com/technetwork/topics/security/cpuapr2008-082075.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8196abdd");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2008 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-396");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/15");
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
# APR2008
patches = make_nested_array();

# RDBMS 11.1.0.6
patches["11.1.0.6"]["db"]["nix"] = make_array("patch_level", "11.1.0.6.2", "CPU", "6864063");
patches["11.1.0.6"]["db"]["win32"] = make_array("patch_level", "11.1.0.6.1", "CPU", "6867178");
patches["11.1.0.6"]["db"]["win64"] = make_array("patch_level", "11.1.0.6.1", "CPU", "6867180");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.10", "CPU", "6864078");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.23", "CPU", "6867107");
# RDBMS 10.2.0.3
patches["10.2.0.3"]["db"]["nix"] = make_array("patch_level", "10.2.0.3.6", "CPU", "6864068");
patches["10.2.0.3"]["db"]["win32"] = make_array("patch_level", "10.2.0.3.20", "CPU", "6867054");
patches["10.2.0.3"]["db"]["win64"] = make_array("patch_level", "10.2.0.3.20", "CPU", "6867056");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.9", "CPU", "6864071");

check_oracle_database(patches:patches, high_risk:TRUE);
