#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103971);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2016-6814",
    "CVE-2016-8735",
    "CVE-2017-10190",
    "CVE-2017-10261",
    "CVE-2017-10292",
    "CVE-2017-10321"
  );
  script_bugtraq_id(
    101329,
    101335,
    101344,
    101350
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2017 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the October 2017
Critical Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities as noted in the October 2017 Critical Patch Update
advisory. Please consult the CVRF details for the applicable CVEs for
additional information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e07fa0e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2017 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8735");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

patches = make_nested_array();
# RDBMS 12.2.0.1
patches["12.2.0.1"]["db"]["nix"] = make_array("patch_level", "12.2.0.1.171017", "CPU", "26710464, 27105253, 27674384, 28163133, 28662603");
patches["12.2.0.1"]["db"]["win"] = make_array("patch_level", "12.2.0.1.171017", "CPU", "26758841");
# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.171017", "CPU", "26635880, 26713565");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.171017", "CPU", "26720785");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.171017", "CPU", "26392168, 26474853");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.171017", "CPU", "26581376");

# OJVM 12.2.0.1
patches["12.2.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.2.0.1.171017", "CPU", "26635944");
patches["12.2.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.2.0.1.171017", "CPU", "26792369");
# OJVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.171017", "CPU", "26635845");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.171017", "CPU", "26792364");
# OJVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.171017", "CPU", "26635834");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.171017", "CPU", "26792358");

check_oracle_database(patches:patches, high_risk:TRUE);
