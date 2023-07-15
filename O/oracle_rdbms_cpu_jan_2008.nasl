#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56059);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2008-0339",
    "CVE-2008-0340",
    "CVE-2008-0341",
    "CVE-2008-0342",
    "CVE-2008-0343",
    "CVE-2008-0344",
    "CVE-2008-0345",
    "CVE-2008-0346",
    "CVE-2008-0347"
  );
  script_bugtraq_id(27229);

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2008 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the January 2008
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Advanced Queuing

  - Core RDBMS

  - Oracle Spatial

  - Oracle Ultra Search

  - Upgrade/Downgrade

  - XML DB");
  # https://www.oracle.com/technetwork/topics/security/cpujan2008-086860.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c33b5b10");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2008 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-061");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/15");
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
# JAN2008
patches = make_nested_array();

# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.9", "CPU", "6647005");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.21", "CPU", "6637274");
# RDBMS 10.2.0.3
patches["10.2.0.3"]["db"]["nix"] = make_array("patch_level", "10.2.0.3.5", "CPU", "6646853");
patches["10.2.0.3"]["db"]["win32"] = make_array("patch_level", "10.2.0.3.16", "CPU", "6637237");
patches["10.2.0.3"]["db"]["win64"] = make_array("patch_level", "10.2.0.3.16", "CPU", "6637239");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.8", "CPU", "6646850");

check_oracle_database(patches:patches);
