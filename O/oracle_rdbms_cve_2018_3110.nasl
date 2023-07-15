#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111680);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-3110");
  script_bugtraq_id(105056);

  script_name(english:"Oracle Database Server CVE-2018-3110");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server may be affected by CVE-2018-3110.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing patches.
It is, therefore, affected by CVE-2018-3110.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/alert-cve-2018-3110-5032149.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f4d652e");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2394520.1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle Security Alert Advisory - CVE-2018-3110.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3110");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/14");

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
# RDBMS 18.3.0.0
patches["18.3"]["db"]["nix"] = make_array("patch_level", "18.3.0.0.180717", "CPU", "28317326");
# RDBMS 12.2.0.1
patches["12.2.0.1"]["db"]["nix"] = make_array("patch_level", "12.2.0.1.180717", "CPU", "28317292");
# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.180717", "CPU", "28317232, 27547329, 28259833");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.180717", "CPU", "27937914, 28247681, 28574555");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.180717", "CPU", "28317175, 28317183");

# OJVM 18.3.0.0
patches["18.3"]["ojvm"]["nix"] = make_array("patch_level", "18.3.0.0.180717", "CPU", "27923415, 28502229");
# OJVM 12.2.0.1
patches["12.2.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.2.0.1.180717", "CPU", "27923353, 28440725");
patches["12.2.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.2.0.1.180810", "CPU", "28416087");
# OJVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.180717", "CPU", "27923320, 28440711");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.180717", "CPU", "28135126");
# OJVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.180717", "CPU", "27923163, 28440700");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.180810", "CPU", "28416098");

check_oracle_database(patches:patches);
