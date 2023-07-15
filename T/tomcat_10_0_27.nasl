#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166806);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/18");

  script_cve_id("CVE-2022-42252");
  script_xref(name:"IAVA", value:"2022-A-0457-S");

  script_name(english:"Apache Tomcat 10.0.0.M1 < 10.0.27 vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 10.0.27. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_10.0.27_security-10 advisory.

  - If Tomcat was configured to ignore invalid HTTP headers via setting rejectIllegalHeader to false (not the
    default), Tomcat did not reject a request containing an invalid Content-Length header making a request
    smuggling attack possible if Tomcat was located behind a reverse proxy that also failed to reject the
    request with the invalid header. (CVE-2022-42252)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/0d089a15047faf9cb3c82f80f4d28febd4798920
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8445ee2a");
  # https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.0.27
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a59e27c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 10.0.27 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42252");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '10.0.27', min:'10.0.0.M1', severity:SECURITY_HOLE, granularity_regex: "^10(\.0)?$");
