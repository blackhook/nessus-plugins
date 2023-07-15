#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151504);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-30639");

  script_name(english:"Apache Tomcat 10.0.3 < 10.0.5 vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is prior to 10.0.5. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_10.0.5_security-10 advisory. Note that Nessus has not tested for this issue but
has instead relied only on the application's self-reported version number.");
  # https://github.com/apache/tomcat/commit/b59099e4ca501a039510334ebe1024971cd6f959
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8c942d2");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=65203");
  # https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb82eb59");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 10.0.5 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30639");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
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

tomcat_check_version(fixed: '10.0.5', min:'10.0.3', severity:SECURITY_WARNING, granularity_regex: "^10(\.0)?$");
