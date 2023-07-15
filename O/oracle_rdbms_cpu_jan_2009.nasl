#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56063);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2008-3973",
    "CVE-2008-3974",
    "CVE-2008-3978",
    "CVE-2008-3979",
    "CVE-2008-3997",
    "CVE-2008-3999",
    "CVE-2008-4015",
    "CVE-2008-5436",
    "CVE-2008-5437",
    "CVE-2008-5439"
  );
  script_bugtraq_id(33177);

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2009 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the January 2009
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Job Queue

  - Oracle OLAP

  - Oracle Spatial

  - Oracle Streams

  - SQL*Plus Windows GUI");
  # https://www.oracle.com/technetwork/topics/security/cpujan2009-097901.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14c7095b");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2009 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Oracle Secure Backup 10.2.0.2 RCE (Windows)");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/13");
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
# JAN2009
patches = make_nested_array();

# RDBMS 11.1.0.6
patches["11.1.0.6"]["db"]["nix"] = make_array("patch_level", "11.1.0.6.5", "CPU", "7592335");
patches["11.1.0.6"]["db"]["win32"] = make_array("patch_level", "11.1.0.6.8", "CPU", "7631980");
patches["11.1.0.6"]["db"]["win64"] = make_array("patch_level", "11.1.0.6.8", "CPU", "7631981");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.13", "CPU", "7592360");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.29", "CPU", "7486619");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.0.3", "CPU", "7592346");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.13", "CPU", "7584866");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.13", "CPU", "7584867");
# RDBMS 10.2.0.3
patches["10.2.0.3"]["db"]["nix"] = make_array("patch_level", "10.2.0.3.9", "CPU", "7592354");
patches["10.2.0.3"]["db"]["win32"] = make_array("patch_level", "10.2.0.3.29", "CPU", "7631956");
patches["10.2.0.3"]["db"]["win64"] = make_array("patch_level", "10.2.0.3.29", "CPU", "7631957");

check_oracle_database(patches:patches);
