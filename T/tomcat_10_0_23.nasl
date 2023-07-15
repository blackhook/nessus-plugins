##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162499);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/08");

  script_cve_id("CVE-2022-34305");
  script_xref(name:"IAVA", value:"2022-A-0398-S");

  script_name(english:"Apache Tomcat 10.0.0.M1 < 10.0.23 vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 10.0.23. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_10.0.23_security-10 advisory.

  - In Apache Tomcat 10.1.0-M1 to 10.1.0-M16, 10.0.0-M1 to 10.0.22, 9.0.30 to 9.0.64 and 8.5.50 to 8.5.81 the
    Form authentication example in the examples web application displayed user provided data without
    filtering, exposing a XSS vulnerability. (CVE-2022-34305)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/1a7e95d9c3ef18c4efb5eb997fd1553a71dc6c80
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3e93497");
  # https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.23
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d58ef8e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 10.0.23 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '10.0.23', min:'10.0.0.M1', severity:SECURITY_WARNING, granularity_regex: "^10(\.0)?$");
