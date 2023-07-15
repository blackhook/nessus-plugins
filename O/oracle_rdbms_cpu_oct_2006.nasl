#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56054);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2006-5332",
    "CVE-2006-5333",
    "CVE-2006-5334",
    "CVE-2006-5335",
    "CVE-2006-5336",
    "CVE-2006-5337",
    "CVE-2006-5338",
    "CVE-2006-5339",
    "CVE-2006-5340",
    "CVE-2006-5341",
    "CVE-2006-5342",
    "CVE-2006-5343",
    "CVE-2006-5344",
    "CVE-2006-5345"
  );
  script_bugtraq_id(20588);

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2006 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2006
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Change Data Capture (CDC)

  - Core RDBMS

  - Database Scheduler

  - Oracle Spatial

  - XMLDB");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2006-095368.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?861d82ff");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2006 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-486");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/17");
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
# OCT2006
patches = make_nested_array();

# RDBMS 10.1.0.4
patches["10.1.0.4"]["db"]["nix"] = make_array("patch_level", "10.1.0.4.7", "CPU", "5490844");
patches["10.1.0.4"]["db"]["win32"] = make_array("patch_level", "10.1.0.4.15", "CPU", "5500878");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.4", "CPU", "5490845");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.8", "CPU", "5500883");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.3", "CPU", "5490848");
patches["10.2.0.2"]["db"]["win32"] = make_array("patch_level", "10.2.0.2.5", "CPU", "5502226");
patches["10.2.0.2"]["db"]["win64"] = make_array("patch_level", "10.2.0.2.5", "CPU", "5500921");
# RDBMS 10.2.0.1
patches["10.2.0.1"]["db"]["nix"] = make_array("patch_level", "10.2.0.1.4", "CPU", "5490846");
patches["10.2.0.1"]["db"]["win32"] = make_array("patch_level", "10.2.0.1.8", "CPU", "5500927");
patches["10.2.0.1"]["db"]["win64"] = make_array("patch_level", "10.2.0.1.8", "CPU", "5500954");
# RDBMS 10.1.0.3
patches["10.1.0.3"]["db"]["nix"] = make_array("patch_level", "10.1.0.3.8", "CPU", "5566825");

check_oracle_database(patches:patches, high_risk:TRUE);
