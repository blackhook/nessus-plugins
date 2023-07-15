#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171714);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2023-24998", "CVE-2023-28708");
  script_xref(name:"IAVA", value:"2023-A-0112-S");
  script_xref(name:"IAVA", value:"2023-A-0156-S");

  script_name(english:"Apache Tomcat 11.0.0.M1 < 11.0.0.M3 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 11.0.0.M3. It is, therefore, affected by a vulnerability
as referenced in the fixed_in_apache_tomcat_11.0.0-m3_security-11 advisory.

  - When using the RemoteIpFilter with requests received from a reverse proxy via HTTP that include the
    X-Forwarded-Proto header set to https, session cookies created by Apache Tomcat 11.0.0-M1 to 11.0.0.-M2,
    10.1.0-M1 to 10.1.5, 9.0.0-M1 to 9.0.71 and 8.5.0 to 8.5.85 did not include the secure attribute. This
    could result in the user agent transmitting the session cookie over an insecure channel. (CVE-2023-28708)

  - Apache Commons FileUpload before 1.5 does not limit the number of request parts to be processed resulting
    in the possibility of an attacker triggering a DoS with a malicious upload or series of uploads. Note
    that, like all of the file upload limits, the new configuration option (FileUploadBase#setFileCountMax) is
    not enabled by default and must be explicitly configured. (CVE-2023-24998)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/c64d496dda1560b5df113be55fbfaefec349b50f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a08f919");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=66471");
  # https://github.com/apache/tomcat/commit/063e2e81ede50c287f737cc8e2915ce7217e886e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56df6968");
  # https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9dba8a0a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 11.0.0.M3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/21");

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

tomcat_check_version(fixed: '11.0.0.M3', min:'11.0.0.M1', severity:SECURITY_WARNING, granularity_regex: "^(11(\.0(\.0)?)?)$");
