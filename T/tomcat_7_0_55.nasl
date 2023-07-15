#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77475);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-0227",
    "CVE-2014-0230",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66801,
    67193,
    67898,
    67899,
    67900,
    67901,
    72717,
    74475
  );
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Apache Tomcat 7.0.x < 7.0.55 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
service listening on the remote host is 7.0.x prior to 7.0.55. It is,
therefore, affected by the following vulnerabilities :

  - A race condition exists in the ssl3_read_bytes()
    function when SSL_MODE_RELEASE_BUFFERS is enabled. This
    allows a remote attacker to inject data across sessions
    or cause a denial of service. (CVE-2010-5298)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that can lead to the execution of
    arbitrary code. Note that this issue only affects
    OpenSSL when used as a DTLS client or server.
    (CVE-2014-0195)

  - An error exists in the do_ssl3_write() function that
    allows a NULL pointer to be dereferenced, resulting in a
    denial of service. Note that this issue is exploitable
    only if 'SSL_MODE_RELEASE_BUFFERS' is enabled.
    (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    can lead to denial of service attacks. Note that this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An unspecified error exists in how ChangeCipherSpec
    messages are processed that can allow an attacker to
    cause usage of weak keying material, leading to
    simplified man-in-the-middle attacks. (CVE-2014-0224)

  - An error exists in 'ChunkedInputFilter.java' due to
    improper handling of attempts to continue reading data
    after an error has occurred. This allows a remote
    attacker, via streaming data with malformed chunked
    transfer coding, to conduct HTTP request smuggling or
    cause a denial of service. (CVE-2014-0227)

  - An error exists due to a failure to limit the size of
    discarded requests. A remote attacker can exploit this
    to exhaust available memory resources, resulting in a
    denial of service condition. (CVE-2014-0230)

  - An unspecified error exists related to anonymous ECDH
    cipher suites that can allow denial of service attacks.
    Note that this issue only affects OpenSSL TLS clients.
    (CVE-2014-3470)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/download-70.cgi#7.0.55");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=56596");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.55 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"7.0.55", min:"7.0.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");

