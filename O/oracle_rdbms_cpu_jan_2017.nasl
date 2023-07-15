#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96611);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-3240", "CVE-2017-3310");
  script_bugtraq_id(95477, 95481);

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the January 2017 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the OJVM component that
    allows an authenticated, remote attacker to execute
    arbitrary code. (CVE-2017-3310)

  - An unspecified flaw exists in the RDBMS Security
    component that allows a combined attacker to disclose
    potentially sensitive information. (CVE-2017-3240)");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89a8e429");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2017 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3310");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

################################################################################
# JAN2017
patches = make_nested_array();

# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.170117", "CPU", "24732082, 24732088");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.170117", "CPU", "25115951");

# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.170117", "CPU", "24917972");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.170117", "CPU", "25112498");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.170117", "CPU", "24917954");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.170117", "CPU", "25043019");

check_oracle_database(patches:patches);
