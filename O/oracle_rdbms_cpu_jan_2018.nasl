#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106188);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-10282",
    "CVE-2017-12617",
    "CVE-2018-2575",
    "CVE-2018-2680",
    "CVE-2018-2699"
  );
  script_bugtraq_id(
    100954,
    102534,
    102547,
    102563,
    102571
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the January 2018
Critical Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities as noted in the January 2018 Critical Patch Update
advisory. Please consult the CVRF details for the applicable CVEs for
additional information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae82f1b1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12617");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat for Windows HTTP PUT Method File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");

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
patches["12.2.0.1"]["db"]["nix"] = make_array("patch_level", "12.2.0.1.180116", "CPU", "27105253, 27674384, 28662603, 28163133");
patches["12.2.0.1"]["db"]["win"] = make_array("patch_level", "12.2.0.1.180116", "CPU", "27162931, 27365680, 28574555");
# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.180116", "CPU", "27010930, 26925311");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.180116", "CPU", "27162953");
# RDBMS 11.2.0.4
#There is no (unix) Database SPU for 11.2.0.4 for the Jan 2018 cycle as there are no new CPU security
#vulnerabilities applicable.
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.180116", "CPU", "26925576");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.180116", "CPU", "27162965");

# OJVM 12.2.0.1
patches["12.2.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.2.0.1.180116", "CPU", "27001739, 27923353");
patches["12.2.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.2.0.1.180116", "CPU", "27162975");
# OJVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.180116", "CPU", "27001733");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.180116", "CPU", "27162998");
# OJVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.180116", "CPU", "26925532");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.180116", "CPU", "27163009");

check_oracle_database(patches:patches);
