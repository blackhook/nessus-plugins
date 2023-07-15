##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161159);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id("CVE-2022-25762");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.21 vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.21. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_9.0.21_security-9 advisory.

  - If a web application sends a WebSocket message concurrently with the WebSocket connection closing when
    running on Apache Tomcat 8.5.0 to 8.5.75 or Apache Tomcat 9.0.0.M1 to 9.0.20, it is possible that the
    application will continue to use the socket after it has been closed. The error handling triggered in this
    case could cause the a pooled object to be placed in the pool twice. This could result in subsequent
    connections using the same object concurrently which could result in data being returned to the wrong use
    and/or other errors. (CVE-2022-25762)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/e2d5a040b962a904db5264b3cb3282c6b05f823c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb880b39");
  # https://github.com/apache/tomcat/commit/7046644bf361b89afc246b6643e24ce2ae60cacc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d63625d1");
  # https://github.com/apache/tomcat/commit/339b40bc07bdba9ded565929b9a3448c5a78f015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6923945f");
  # https://github.com/apache/tomcat/commit/65fb1ee548111021edde247f3b3c409ec95a5183
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?345e3801");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.21
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?deb227c6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.21 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25762");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/07");
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

tomcat_check_version(fixed: '9.0.21', min:'9.0.0.M1', severity:SECURITY_HOLE, granularity_regex: "^9(\.0)?$");
