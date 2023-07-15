#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150938);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-11996");
  script_xref(name:"IAVA", value:"2020-A-0292-S");

  script_name(english:"Apache Tomcat 10.0.0.M1 < 10.0.0.M6 vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 10.0.0.M6. It is, therefore, affected by a vulnerability
as referenced in the fixed_in_apache_tomcat_10.0.0-m6_security-10 advisory.

  - A specially crafted sequence of HTTP/2 requests sent to Apache Tomcat 10.0.0-M1 to 10.0.0-M5, 9.0.0.M1 to
    9.0.35 and 8.5.0 to 8.5.55 could trigger high CPU usage for several seconds. If a sufficient number of
    such requests were made on concurrent HTTP/2 connections, the server could become unresponsive.
    (CVE-2020-11996)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/9434a44d3449d620b1be70206819f8275b4a7509
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1261b2b");
  # https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.0-M6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d35c3740");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 10.0.0.M6 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11996");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '10.0.0.M6', min:'10.0.0.M1', severity:SECURITY_WARNING, granularity_regex: "^(10(\.0(\.0)?)?)$");
