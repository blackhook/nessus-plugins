#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62662);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2012-1751",
    "CVE-2012-3132",
    "CVE-2012-3137",
    "CVE-2012-3146",
    "CVE-2012-3151"
  );
  script_bugtraq_id(
    54884,
    55651,
    55947,
    55949,
    55950
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2012 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2012 Critical
Patch Update (CPU) and is, therefore, potentially affected by security
issues in the Core RDBMS.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/525765/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/525766/30/0/threaded");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87547c81");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2012 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3132");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

################################################################################
# OCT2012
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.13", "CPU", "14390384, 14275623");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.50", "CPU", "14672312");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.50", "CPU", "14672313");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.8", "CPU", "14390377, 14275621");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.22", "CPU", "14672267");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.22", "CPU", "14672268");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.4", "CPU", "14390252, 14275605");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.11", "CPU", "14613222");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.11", "CPU", "14613223");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.9", "CPU", "14390396, 14275629");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.19", "CPU", "14553356");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.19", "CPU", "14553358");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.14", "CPU", "14390410, 14275630");

check_oracle_database(patches:patches);
