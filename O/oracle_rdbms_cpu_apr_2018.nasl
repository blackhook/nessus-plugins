#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109205);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-2841");
  script_bugtraq_id(103839);

  script_name(english:"Oracle Database Server Java VM Unspecified Remote Code Execution (April 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the April 2018 Critical
Patch Update (CPU). It is, therefore, affected by a remote code
execution vulnerability as noted in the April 2018 Critical Patch
Update advisory. Please consult the CVRF details for the applicable
CVEs for additional information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76507bf8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2841");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

patches = make_nested_array();
# RDBMS 12.2.0.1
patches["12.2.0.1"]["db"]["nix"] = make_array("patch_level", "12.2.0.1.180417", "CPU", "27674384, 27726453");
patches["12.2.0.1"]["db"]["win"] = make_array("patch_level", "12.2.0.1.180417", "CPU", "27426753");
# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.180417", "CPU", "27338041, 27547329, 28259833, 28349311, 27726471, 27726492");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.180417", "CPU", "27440294");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.180417", "CPU", "27338049, 27726497, 27734982, 28204707");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.180417", "CPU", "27381640, 27695940, 28265827");

# OJVM 12.2.0.1
patches["12.2.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.2.0.1.180417", "CPU", "27475613, 27726453, 27923353, 28440725");
patches["12.2.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.2.0.1.180417", "CPU", "27650410");
# OJVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.180417", "CPU", "27475603, 27726471, 27726492, 27923320, 28440711");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.180417", "CPU", "27650403");
# OJVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.180417", "CPU", "27475598, 27726497, 27923163, 28440700");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.180417", "CPU", "27650399");

check_oracle_database(patches:patches);
