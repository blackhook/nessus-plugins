#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154149);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id("CVE-2021-42340");
  script_xref(name:"IAVA", value:"2021-A-0479-S");

  script_name(english:"Apache Tomcat 10.1.0.M1 < 10.1.0.M6 vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 10.1.0.M6. It is, therefore, affected by a vulnerability
as referenced in the fixed_in_apache_tomcat_10.1.0-m6_security-10 advisory.

  - The fix for bug 63362 present in Apache Tomcat 10.1.0-M1 to 10.1.0-M5, 10.0.0-M1 to 10.0.11, 9.0.40 to
    9.0.53 and 8.5.60 to 8.5.71 introduced a memory leak. The object introduced to collect metrics for HTTP
    upgrade connections was not released for WebSocket connections once the connection was closed. This
    created a memory leak that, over time, could lead to a denial of service via an OutOfMemoryError.
    (CVE-2021-42340)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=63362");
  # https://github.com/apache/tomcat/commit/d5a6660cba7f51589468937bf3bbad4db7810371
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0eca2273");
  # https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.0-M6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75e2082d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 10.1.0.M6 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42340");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/14");

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

tomcat_check_version(fixed: '10.1.0.M6', min:'10.1.0.M1', severity:SECURITY_WARNING, granularity_regex: "^(10(\.1(\.0)?)?)$");
