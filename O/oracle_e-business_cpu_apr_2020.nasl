#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135582);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-2750",
    "CVE-2020-2753",
    "CVE-2020-2772",
    "CVE-2020-2789",
    "CVE-2020-2794",
    "CVE-2020-2796",
    "CVE-2020-2807",
    "CVE-2020-2808",
    "CVE-2020-2809",
    "CVE-2020-2810",
    "CVE-2020-2813",
    "CVE-2020-2815",
    "CVE-2020-2817",
    "CVE-2020-2818",
    "CVE-2020-2819",
    "CVE-2020-2820",
    "CVE-2020-2821",
    "CVE-2020-2822",
    "CVE-2020-2823",
    "CVE-2020-2824",
    "CVE-2020-2825",
    "CVE-2020-2826",
    "CVE-2020-2827",
    "CVE-2020-2831",
    "CVE-2020-2832",
    "CVE-2020-2833",
    "CVE-2020-2834",
    "CVE-2020-2835",
    "CVE-2020-2836",
    "CVE-2020-2837",
    "CVE-2020-2838",
    "CVE-2020-2839",
    "CVE-2020-2840",
    "CVE-2020-2841",
    "CVE-2020-2842",
    "CVE-2020-2843",
    "CVE-2020-2844",
    "CVE-2020-2845",
    "CVE-2020-2846",
    "CVE-2020-2847",
    "CVE-2020-2848",
    "CVE-2020-2849",
    "CVE-2020-2850",
    "CVE-2020-2852",
    "CVE-2020-2854",
    "CVE-2020-2855",
    "CVE-2020-2856",
    "CVE-2020-2857",
    "CVE-2020-2858",
    "CVE-2020-2860",
    "CVE-2020-2861",
    "CVE-2020-2862",
    "CVE-2020-2863",
    "CVE-2020-2864",
    "CVE-2020-2866",
    "CVE-2020-2870",
    "CVE-2020-2871",
    "CVE-2020-2872",
    "CVE-2020-2873",
    "CVE-2020-2874",
    "CVE-2020-2876",
    "CVE-2020-2877",
    "CVE-2020-2878",
    "CVE-2020-2879",
    "CVE-2020-2880",
    "CVE-2020-2881",
    "CVE-2020-2882",
    "CVE-2020-2885",
    "CVE-2020-2886",
    "CVE-2020-2887",
    "CVE-2020-2888",
    "CVE-2020-2889",
    "CVE-2020-2890",
    "CVE-2020-2956"
  );

  script_name(english:"Oracle Oracle E-Business Suite (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the April 2020 Oracle Critical Patch Update (CPU) advisory, including the
following:

  - A vulnerability in the Oracle Email Center product of Oracle E-Business Suite (component: Email Address
    list and Message Display) of supported versions 12.1.1-12.1.3 and 12.2.3-12.2.9 which allows unauthorized
    access to critical data or complete access to all Oracle Email Center accessible data as well as
    unauthorized update, insert or delete access to some Oracle Email Center accessible data by an
    unauthenticated, remote attacker. (CVE-2020-2794)
  
  - A vulnerability in the Oracle Email Center product of Oracle E-Business Suite (component: Message Display)
    of supported versions 12.1.1-12.1.3 and 12.2.3-12.2.9 which allows unauthorized access to critical data or
    complete access to all Oracle Email Center accessible data as well as unauthorized update, insert or
    delete access to some Oracle Email Center accessible data by an unauthenticated, remote attacker.
    (CVE-2020-2796)
  
  - A vulnerability in the Oracle Marketing Encyclopedia System product of Oracle E-Business Suite (component:
    Administration) of supported versions 12.1.1-12.1.3 which allows unauthorized access to critical data or
    complete access to all Oracle Marketing Encyclopedia System accessible data as well as unauthorized
    update, insert or delete access to some Oracle Marketing Encyclopedia System accessible data by an
    unauthenticated, remote attacker. (CVE-2020-2807)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2890");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2838");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

fix_date = '202004';

app_name = 'Oracle E-Business';
version = get_kb_item_or_exit('Oracle/E-Business/Version');
patched_versions = get_kb_item('Oracle/E-Business/patched_versions');

# check if patched
version_regex = "(^|[^0-9])" + version + "\." + fix_date + "([^0-9]|$)";
if (!empty_or_null(patched_versions) && patched_versions =~ version_regex)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# Report fixed version and required patches
fix_version = version;

# 12.1.1 - 12.1.3
if (version =~ "^12\.1\.[1-3]($|[^0-9])")
  fix_patches = '30812013';

# 12.2.0 - 12.2.3
else if (version =~ "^12\.2.[0-3]($|[^0-9])") 
{
  fix_version = '12.2.3';
  fix_patches = '30812019';
}
# 12.2.4 
else if (version =~ "^12\.2\.4($|[^0-9])")
  fix_patches = make_list('30812019');
# 12.2.5
else if (version =~ "^12\.2\.5($|[^0-9])")
  fix_patches = make_list('30812019', '30958713');
# 12.2.6
else if (version =~ "^12\.2\.6($|[^0-9])")
  fix_patches = make_list('30812019', '30980446', '30739126');
# 12.2.7-8
else if (version =~ "^12\.2\.[78]($|[^0-9])")
  fix_patches = make_list('30812019', '30980446', '30948437');
# 12.2.9
else if (version =~ "^12\.2\.9($|[^0-9])")
  fix_patches = make_list('30812019', '30980446');
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version);

report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_version +
    '\n  Required Patches  : ' + join(sep:', ', fix_patches);

security_report_v4(port:0,extra:report,severity:SECURITY_WARNING);
