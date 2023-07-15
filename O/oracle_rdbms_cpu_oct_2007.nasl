#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56058);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2007-5504",
    "CVE-2007-5505",
    "CVE-2007-5506",
    "CVE-2007-5507",
    "CVE-2007-5508",
    "CVE-2007-5509",
    "CVE-2007-5510",
    "CVE-2007-5511",
    "CVE-2007-5512",
    "CVE-2007-5513",
    "CVE-2007-5514",
    "CVE-2007-5515",
    "CVE-2007-5520",
    "CVE-2007-5530",
    "CVE-2007-5531",
    "CVE-2007-5554"
  );
  script_bugtraq_id(26235);

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2007 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2007
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Advanced Security Option

  - Advanced Queuing

  - Core RDBMS

  - Database Control

  - Export

  - Import

  - Oracle Database Vault

  - Oracle Help for Web

  - Oracle Internet Directory

  - Oracle Net Services

  - Oracle Text

  - Spatial

  - SQL Execution

  - XML DB

  - Workspace Manager");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2007-092913.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c50c7c4d");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2007 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 89, 119, 200, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/16");
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
# OCT2007
patches = make_nested_array();

# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.8", "CPU", "6395024");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.19", "CPU", "6408393");
# RDBMS 10.2.0.3
patches["10.2.0.3"]["db"]["nix"] = make_array("patch_level", "10.2.0.3.4", "CPU", "6394981");
patches["10.2.0.3"]["db"]["win32"] = make_array("patch_level", "10.2.0.3.12", "CPU", "6430171");
patches["10.2.0.3"]["db"]["win64"] = make_array("patch_level", "10.2.0.3.12", "CPU", "6430174");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.7", "CPU", "6394997");
patches["10.2.0.2"]["db"]["win32"] = make_array("patch_level", "10.2.0.2.9", "CPU", "6397028");
patches["10.2.0.2"]["db"]["win64"] = make_array("patch_level", "10.2.0.2.9", "CPU", "6397030");
patches["10.2.0.2"]["db"]["win"] = make_array("patch_level", "10.2.0.2.9", "CPU", "6397029, 6397028, 6397030");

check_oracle_database(patches:patches, high_risk:TRUE);
