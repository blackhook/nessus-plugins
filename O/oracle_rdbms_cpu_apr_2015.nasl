#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82903);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-0455",
    "CVE-2015-0457",
    "CVE-2015-0479",
    "CVE-2015-0483"
  );
  script_bugtraq_id(
    74076,
    74079,
    74084,
    74090
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2015 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the April 2015 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities in the following components :

  - Core RDBMS (CVE-2015-0483)
  - Java VM (CVE-2015-0457)
  - XDB-XML Database (CVE-2015-0455)
  - XDK and XDB-XML Database (CVE-2015-0479)");
  # https://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56618dc1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2015 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");

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
# APR2015
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.23", "CPU", "20299020, 20299012");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.60", "CPU", "20420390");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.60", "CPU", "20420391");
# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.3", "CPU", "20299023");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.4", "CPU", "20684004");
# RDBMS 12.1.0.1
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.7", "CPU", "20299016");
patches["12.1.0.1"]["db"]["win"] = make_array("patch_level", "12.1.0.1.18", "CPU", "20558101");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.14", "CPU", "20299010, 20299017");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.37", "CPU", "20420394");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.37", "CPU", "20420395");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.6", "CPU", "20299015, 20299013");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.15", "CPU", "20544696");
# JVM 11.2.0.3
patches["11.2.0.3"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.3.3", "CPU", "20406220");
patches["11.2.0.3"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.3.3", "CPU", "20391185");
# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.3", "CPU", "20415564");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.2", "CPU", "20391199");
# JVM 11.1.0.7
patches["11.1.0.7"]["ojvm"]["nix"] = make_array("patch_level", "11.1.0.7.3", "CPU", "20406213");
patches["11.1.0.7"]["ojvm"]["win"] = make_array("patch_level", "11.1.0.7.3", "CPU", "20391156");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.3", "CPU", "20406239");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.3", "CPU", "20225988");
# JVM 12.1.0.1
patches["12.1.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.1.3", "CPU", "20406245");
patches["12.1.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.1.3", "CPU", "20225909");

check_oracle_database(patches:patches, high_risk:TRUE);
