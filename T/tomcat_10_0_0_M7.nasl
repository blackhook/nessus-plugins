#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150936);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-13934", "CVE-2020-13935");
  script_xref(name:"IAVA", value:"2020-A-0316-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Apache Tomcat 10.0.0.M1 < 10.0.0.M7 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 10.0.0.M7. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_10.0.0-m7_security-10 advisory.

  - The payload length in a WebSocket frame was not correctly validated in Apache Tomcat 10.0.0-M1 to
    10.0.0-M6, 9.0.0.M1 to 9.0.36, 8.5.0 to 8.5.56 and 7.0.27 to 7.0.104. Invalid payload lengths could
    trigger an infinite loop. Multiple requests with invalid payload lengths could lead to a denial of
    service. (CVE-2020-13935)

  - An h2c direct connection to Apache Tomcat 10.0.0-M1 to 10.0.0-M6, 9.0.0.M5 to 9.0.36 and 8.5.1 to 8.5.56
    did not release the HTTP/1.1 processor after the upgrade to HTTP/2. If a sufficient number of such
    requests were made, an OutOfMemoryException could occur leading to a denial of service. (CVE-2020-13934)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/1c1c77b0efb667cea80b532440b44cea1dc427c3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?93d9487c");
  # https://github.com/apache/tomcat/commit/c9167ae30f3b03b112f3d81772e3450b7d0e6a25
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5037be9d");
  # https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.0-M7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?301b9be1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 10.0.0.M7 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13935");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/05");
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

tomcat_check_version(fixed: '10.0.0.M7', min:'10.0.0.M1', severity:SECURITY_WARNING, granularity_regex: "^(10(\.0(\.0)?)?)$");
