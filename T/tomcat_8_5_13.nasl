#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99368);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-5647", "CVE-2017-5650", "CVE-2017-5651");
  script_bugtraq_id(97529, 97531, 97544);

  script_name(english:"Apache Tomcat 8.5.x < 8.5.13 / 9.0.x < 9.0.0.M19 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
service running on the remote host is 8.5.x prior to 8.5.13 or 
9.0.x prior to 9.0.0.M19. It is therefore affected by multiple 
vulnerabilities :

  - A flaw exists in the handling of pipelined requests when
    send file processing is used that results in the
    pipelined request being lost when processing of the
    previous request has completed, causing responses to be
    sent for the wrong request. An unauthenticated, remote
    attacker can exploit this to disclose sensitive
    information. (CVE-2017-5647)

  - A flaw exists in the handling of HTTP/2 GOAWAY frames
    for a connection due to streams associated with the
    connection not being properly closed if the connection
    was currently waiting for a WINDOW_UPDATE before
    allowing the application to write more data. Each stream
    consumes a processing thread in the system. An
    unauthenticated, remote attacker can exploit this issue,
    via a series of specially crafted HTTP/2 requests, to
    consume all available threads, resulting in a denial of
    service condition. (CVE-2017-5650)

  - A flaw exists in HTTP connectors when processing send
    files. If processing completed quickly, it was possible
    to add the processor to the processor cache twice, which
    allows the same processor to be used for multiple
    requests. An unauthenticated, remote attacker can
    exploit this to disclose sensitive information from
    other sessions or cause unexpected errors.
    (CVE-2017-5651)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M19
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26fc2208");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.13");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.13 / 9.0.0.M19 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");
tomcat_check_version(fixed:make_list("8.5.13", "9.0.0.M19"), severity:SECURITY_HOLE, granularity_regex:"^(8(\.5)?|9(\.0)?)$");


