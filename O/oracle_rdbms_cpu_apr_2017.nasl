#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99480);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-3486", "CVE-2017-3567");
  script_bugtraq_id(97870, 97873);

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the April 2017 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the SQL*Plus component
    that allows a local attacker to impact confidentiality,
    integrity, and availability. (CVE-2017-3486)

  - An unspecified flaw exists in the OJVM component that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3567)");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?623d2c22");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2017 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3486");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");

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

patches = make_nested_array();

# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.170418", "CPU", "25171037, 25433352, 26022196");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.170418", "CPU", "25632533, 25872779, 26161724");
# RDBMS 11.2.0.4 #
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.170418", "CPU", "25369547, 24732075, 25869727");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.170418", "CPU", "25632525, 25874796");

# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.170418", "CPU", "25437695, 26027162");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.170418", "CPU", "25590993");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.170418", "CPU", "25434033, 26027154");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.170418", "CPU", "25590979");

check_oracle_database(patches:patches);
