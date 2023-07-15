#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56653);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2011-2301",
    "CVE-2011-2322",
    "CVE-2011-3511",
    "CVE-2011-3512",
    "CVE-2011-3525"
  );
  script_bugtraq_id(
    50197,
    50199,
    50203,
    50219,
    50222
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2011 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2011
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Oracle Text

  - Application Express

  - Core RDBMS

  - Database Vault");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/technetwork/topics/security/cpuoct2011-330135.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2011 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/26");

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
# OCT2011
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.9", "CPU", "12828097, 12827740");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.42", "CPU", "12914915");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.42", "CPU", "12914916");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.4", "CPU", "12828071, 12827726");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.12", "CPU", "13038787");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.12", "CPU", "13038788");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.23", "CPU", "12828135");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.43", "CPU", "12914905");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.5", "CPU", "12828105, 12827745");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.11", "CPU", "12914911");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.11", "CPU", "12914913");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.10", "CPU", "12828112, 12827778");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.47", "CPU", "12914908");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.47", "CPU", "12914910");

check_oracle_database(patches:patches, high_risk:TRUE);
