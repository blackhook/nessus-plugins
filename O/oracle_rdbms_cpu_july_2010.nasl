#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47718);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2010-0892",
    "CVE-2010-0900",
    "CVE-2010-0901",
    "CVE-2010-0902",
    "CVE-2010-0903",
    "CVE-2010-0911"
  );
  script_bugtraq_id(
    41621,
    41635,
    41639,
    41643
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2010 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the July 2010 Critical
Patch Update (CPU) and therefore is potentially affected by security
issues in the following components :

  - Listener

  - Net Foundation Layer

  - Oracle OLAP

  - Application Express

  - Network Layer

  - Export");
  # https://www.oracle.com/technetwork/topics/security/cpujul2010-155308.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d4821a1");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2010 Oracle Critical
Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("oracle_rdbms_cpu_func.inc");

################################################################################
# JUL2010
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.4", "CPU", "9655014, 9654987");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.30", "CPU", "9869911");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.30", "CPU", "9869912");
# RDBMS 11.2.0.1
patches["11.2.0.1"]["db"]["nix"] = make_array("patch_level", "11.2.0.1.2", "CPU", "9655013, 9654983");
patches["11.2.0.1"]["db"]["win32"] = make_array("patch_level", "11.2.0.1.3", "CPU", "9736864");
patches["11.2.0.1"]["db"]["win64"] = make_array("patch_level", "11.2.0.1.3", "CPU", "9736865");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.19", "CPU", "9655023");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.39", "CPU", "9683651");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.5", "CPU", "9655017, 9654991");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.38", "CPU", "9777076");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.38", "CPU", "9777078");

check_oracle_database(patches:patches, high_risk:TRUE);
