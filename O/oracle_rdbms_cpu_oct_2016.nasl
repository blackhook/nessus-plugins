#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94201);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-3562",
    "CVE-2016-5497",
    "CVE-2016-5498",
    "CVE-2016-5499",
    "CVE-2016-5505",
    "CVE-2016-5516",
    "CVE-2016-5555",
    "CVE-2016-5572"
  );
  script_bugtraq_id(
    93613,
    93615,
    93620,
    93626,
    93629,
    93631,
    93634,
    93640
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2016 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the October 2016 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the RDBMS Security and
    SQL*Plus component that allows an authenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-3562)

  - An unspecified flaw exists in the RDBMS Security
    component that allows a local attacker to gain elevated
    privileges. (CVE-2016-5497)

  - Multiple unspecified flaws exist in the RDBMS Security
    component that allow a local attacker to disclose
    sensitive information. (CVE-2016-5498, CVE-2016-5499)

  - An unspecified flaw exists in the RDBMS Programmable
    Interface component that allows a local attacker to
    disclose sensitive information. (CVE-2016-5505)

  - An unspecified flaw exists in the Kernel PDB component
    that allows a local attacker to cause a denial of
    service condition. (CVE-2016-5516)

  - An unspecified flaw exists in the OJVM component that
    allows an authenticated, remote attacker to execute
    arbitrary code. (CVE-2016-5555)

  - An unspecified flaw exists in the Kernel PDB component
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-5572)");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2016 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5555");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/21");

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
# OCT2016
patches = make_nested_array();

# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.161018", "CPU", "24006101, 24448103");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.161018", "CPU", "24591642");
# RDBMS 11.2.0.4 #
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.161018", "CPU", "24433711, 24006111");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.161018", "CPU", "24591646");

# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.161018", "CPU", "24315824");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.161018", "CPU", "24591630");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.161018", "CPU", "24315821");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.161018", "CPU", "24591637");

check_oracle_database(patches:patches);
