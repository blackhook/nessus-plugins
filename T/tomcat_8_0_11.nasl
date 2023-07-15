#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77476);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66801,
    67193,
    67898,
    67899,
    67900,
    67901
  );
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Apache Tomcat 8.0.x < 8.0.11 Multiple OpenSSL Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
server running on the remote host is 8.0.x prior to 8.0.11. It is,
therefore, affected by multiple vulnerabilities in the bundled version
of OpenSSL :

  - An error exists in the function 'ssl3_read_bytes' that
    could allow data to be injected into other sessions or
    allow denial of service attacks. Note that this issue
    is exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2010-5298)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that could lead to the execution of
    arbitrary code. Note that this issue only affects
    OpenSSL when used as a DTLS client or server.
    (CVE-2014-0195)

  - An error exists in the function 'do_ssl3_write' that
    could allow a NULL pointer to be dereferenced leading to
    denial of service attacks. Note that this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    could lead to denial of service attacks. Note that this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An unspecified error exists that could allow an attacker
    to cause usage of weak keying material leading to
    simplified man-in-the-middle attacks. (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    cipher suites that could allow denial of service
    attacks. Note that this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/download-80.cgi#8.0.11");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=56596");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"Update to Apache Tomcat version 8.0.11 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0195");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "os_fingerprint.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tc_paranoia = FALSE;

# Only fire on Windows if low paranoia
if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Windows" >!< os) audit(AUDIT_OS_NOT, "Microsoft Windows");
  tc_paranoia = TRUE;
}

tomcat_check_version(fixed:"8.0.11", min:"8.0.0", severity:SECURITY_WARNING, granularity_regex:"^8(\.0)?$", paranoid:tc_paranoia);

