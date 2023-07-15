#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88146);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-4921",
    "CVE-2015-4923",
    "CVE-2015-4925",
    "CVE-2016-0461",
    "CVE-2016-0467",
    "CVE-2016-0472",
    "CVE-2016-0499"
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2016 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the January 2016 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities in the following components :

  - Database Vault (CVE-2015-4921)
  - Java VM (CVE-2016-0499)
  - Security (CVE-2016-0467)
  - Workspace Manager (CVE-2015-4925)
  - XDB - XML Database (CVE-2016-0461, CVE-2016-0472)
  - XML Developer's Kit for C (CVE-2015-4923)");
  # https://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d13bbe45");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2016 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

################################################################################
# JAN2016
patches = make_nested_array();

# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.160119", "CPU", "21948354");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.160119", "CPU", "22310559");
# RDBMS 12.1.0.1 #
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.160119", "CPU", "21951844");
patches["12.1.0.1"]["db"]["win"] = make_array("patch_level", "12.1.0.1.160119", "CPU", "22494866");
# RDBMS 11.2.0.4 #
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.160119", "CPU", "21972320, 21948347");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.160119", "CPU", "22310544");

# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.160119", "CPU", "22139226");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.160119", "CPU", "22311086");
# JVM 12.1.0.1
patches["12.1.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.1.160119", "CPU", "22139235");
patches["12.1.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.1.160119", "CPU", "22311072");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.160119", "CPU", "22139245");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.160119", "CPU", "22311053");

check_oracle_database(patches:patches, high_risk:TRUE);
