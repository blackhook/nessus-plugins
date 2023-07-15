#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157117);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id("CVE-2022-23181");
  script_xref(name:"IAVA", value:"2020-A-0225-S");
  script_xref(name:"IAVA", value:"2020-A-0324");

  script_name(english:"Apache Tomcat 9.0.35 < 9.0.58 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.58. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_9.0.58_security-9 advisory.

  - The fix for bug CVE-2020-9484 introduced a time of check, time of use vulnerability into Apache Tomcat
    10.1.0-M1 to 10.1.0-M8, 10.0.0-M5 to 10.0.14, 9.0.35 to 9.0.56 and 8.5.55 to 8.5.73 that allowed a local
    attacker to perform actions with the privileges of the user that the Tomcat process is using. This issue
    is only exploitable when Tomcat is configured to persist sessions using the FileStore. (CVE-2022-23181)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/1385c624b4a1e994426e810075c850edc38a700e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad539974");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.58
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a99149f8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.58 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat", "Settings/ParanoidReport");

  exit(0);
}

include('tomcat_version.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

tomcat_check_version(fixed: '9.0.58', min:'9.0.35', severity:SECURITY_NOTE, granularity_regex: "^9(\.0)?$");
