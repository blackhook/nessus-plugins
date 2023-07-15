#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56056);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2007-2108",
    "CVE-2007-2109",
    "CVE-2007-2110",
    "CVE-2007-2111",
    "CVE-2007-2112",
    "CVE-2007-2113",
    "CVE-2007-2114",
    "CVE-2007-2115",
    "CVE-2007-2116",
    "CVE-2007-2117",
    "CVE-2007-2118",
    "CVE-2007-2119",
    "CVE-2007-2129",
    "CVE-2007-2130"
  );
  script_bugtraq_id(23532);

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2007 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the April 2007 Critical
Patch Update (CPU) and therefore is potentially affected by security
issues in the following components :

  - Adanced Queuing

  - Advanced Replication

  - Authentication

  - Core RDBMS

  - Oracle Agent

  - Oracle Data Capture (CDC)

  - Oracle Instant Client

  - Oracle Streams

  - Oracle Text

  - Oracle Workflow Cartridge

  - Rules Manager, Expressions Filter

  - Ultra Search

  - Upgrade/Downgrade");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2007-090632.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e64d5c5a");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2007 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-804");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}
include("oracle_rdbms_cpu_func.inc");

################################################################################
# APR2007
patches = make_nested_array();

# RDBMS 10.1.0.4
patches["10.1.0.4"]["db"]["nix"] = make_array("patch_level", "10.1.0.4.9", "CPU", "5901876");
patches["10.1.0.4"]["db"]["win32"] = make_array("patch_level", "10.1.0.4.17", "CPU", "5909871");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.6", "CPU", "5901877");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.13", "CPU", "5907304");
# RDBMS 10.2.0.3
patches["10.2.0.3"]["db"]["nix"] = make_array("patch_level", "10.2.0.3.2", "CPU", "5901891");
patches["10.2.0.3"]["db"]["win32"] = make_array("patch_level", "10.2.0.3.4", "CPU", "5948242");
patches["10.2.0.3"]["db"]["win64"] = make_array("patch_level", "10.2.0.3.4", "CPU", "5948243");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.5", "CPU", "5901881");
patches["10.2.0.2"]["db"]["win32"] = make_array("patch_level", "10.2.0.2.7", "CPU", "5912173");
patches["10.2.0.2"]["db"]["win64"] = make_array("patch_level", "10.2.0.2.7", "CPU", "5912179");
# RDBMS 10.2.0.1
patches["10.2.0.1"]["db"]["nix"] = make_array("patch_level", "10.2.0.1.6", "CPU", "5901880");

check_oracle_database(patches:patches, high_risk:TRUE);
