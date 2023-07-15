##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161181);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id("CVE-2022-25762");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.76 vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.76. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_8.5.76_security-8 advisory.

  - If a web application sends a WebSocket message concurrently with the WebSocket connection closing when
    running on Apache Tomcat 8.5.0 to 8.5.75 or Apache Tomcat 9.0.0.M1 to 9.0.20, it is possible that the
    application will continue to use the socket after it has been closed. The error handling triggered in this
    case could cause the a pooled object to be placed in the pool twice. This could result in subsequent
    connections using the same object concurrently which could result in data being returned to the wrong use
    and/or other errors. (CVE-2022-25762)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/01f2cf25b270a84d0daeefc4f215aa2f56e1df99
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8992e36");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.76
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97cadf8c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.76 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25762");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '8.5.76', min:'8.5.0', severity:SECURITY_HOLE, granularity_regex: "^8(\.5)?$");
