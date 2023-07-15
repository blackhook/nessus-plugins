#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62986);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887");
  script_bugtraq_id(56403);

  script_name(english:"Apache Tomcat 5.5.x < 5.5.36 DIGEST Authentication Multiple Security Weaknesses");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple security
weaknesses.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 5.5.x listening on the remote host is prior to 5.5.36. It is,
therefore, affected by the following vulnerabilities :

  - Replay-countermeasure functionality in HTTP Digest
    Access Authentication tracks cnonce values instead of
    nonce values, which makes it easier for attackers to
    bypass access restrictions by sniffing the network for
    valid requests.  (CVE-2012-5885)

  - HTTP Digest Access Authentication implementation caches
    information about the authenticated user, which could
    potentially allow an attacker to bypass authentication
    via session ID. (CVE-2012-5886)

  - HTTP Digest Access Authentication implementation does
    not properly check for stale nonce values with
    enforcement of proper credentials,	which allows an
    attacker to bypass restrictions by sniffing requests.
    (CVE-2012-5887)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.36");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 5.5.36 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5885");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"5.5.36", min:"5.5.0", severity:SECURITY_WARNING, granularity_regex:"^5(\.5)?$");

