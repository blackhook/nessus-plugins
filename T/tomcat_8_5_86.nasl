#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173256);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2023-28708");
  script_xref(name:"IAVA", value:"2023-A-0156-S");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.86");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.86. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_8.5.86_security-8 advisory.

  - When using the RemoteIpFilter with requests received from a reverse proxy via HTTP that include the
    X-Forwarded-Proto header set to https, session cookies created by Apache Tomcat 11.0.0-M1 to 11.0.0.-M2,
    10.1.0-M1 to 10.1.5, 9.0.0-M1 to 9.0.71 and 8.5.0 to 8.5.85 did not include the secure attribute. This
    could result in the user agent transmitting the session cookie over an insecure channel. (CVE-2023-28708)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/5b72c94e8b2c4ada63a1d91dc527bf4d8fd1f510
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bff3d148");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=66471");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.86
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6187e29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.86 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '8.5.86', min:'8.5.0', severity:SECURITY_WARNING, granularity_regex: "^8(\.5)?$");
