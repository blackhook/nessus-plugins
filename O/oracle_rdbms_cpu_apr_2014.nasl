#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73576);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-2406", "CVE-2014-2408");
  script_bugtraq_id(66884, 66889);

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2014 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the April 2014 Critical
Patch Update (CPU) and is, therefore, potentially affected by security
issues in the Core RDBMS component.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef1fc2a6");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2014 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

################################################################################
# APR2014
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.19", "CPU", "18139703, 18031726");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.56", "CPU", "18372257");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.56", "CPU", "18372258");
# RDBMS 12.1.0.1
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.3", "CPU", "18031528");
patches["12.1.0.1"]["db"]["win"] = make_array("patch_level", "12.1.0.1.7", "CPU", "18448604");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.10", "CPU", "18139695, 18031683");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.30", "CPU", "18372243");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.30", "CPU", "18372244");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.2", "CPU", "18139690, 18031668");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.4", "CPU", "18296644");

check_oracle_database(patches:patches, high_risk:TRUE);
