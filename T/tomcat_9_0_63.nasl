##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160894);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id("CVE-2022-29885");
  script_xref(name:"IAVA", value:"2022-A-0222-S");

  script_name(english:"Apache Tomcat 9.0.13 < 9.0.63 vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.63. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_9.0.63_security-9 advisory.

  - The documentation of Apache Tomcat 10.1.0-M1 to 10.1.0-M14, 10.0.0-M1 to 10.0.20, 9.0.13 to 9.0.62 and
    8.5.38 to 8.5.78 for the EncryptInterceptor incorrectly stated it enabled Tomcat clustering to run over an
    untrusted network. This was not correct. While the EncryptInterceptor does provide confidentiality and
    integrity protection, it does not protect against all risks associated with running over any untrusted
    network, particularly DoS risks. (CVE-2022-29885)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/eaafd28296c54d983e28a47953c1f5cb2c334f48
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?718f086d");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.63
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c4c7b12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.63 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29885");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"III");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '9.0.63', min:'9.0.13', severity:SECURITY_WARNING, granularity_regex: "^9(\.0)?$");
