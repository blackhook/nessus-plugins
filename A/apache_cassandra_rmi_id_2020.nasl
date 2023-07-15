##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143421);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/03");

  script_cve_id("CVE-2020-13946");

  script_name(english:"Apache Cassandra < 2.1.22 / 2.2.x < 2.2.18 / 3.0.x < 3.0.22 / 3.11.x < 3.11.8 Information Disclosure Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A database running on the remote host is affected by a information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Cassandra running on the remote host is prior to 2.1.22, 2.2.18, 3.0.22, 3.11.8 and 4.0-beta2.  
It is, therefore, affected by information disclosure vulnerability. An unauthenticated, local attacker without access 
to the Apache Cassandra process or configuration files can manipulate the RMI registry to perform a man-in-the-middle 
attack and capture user names and passwords used to access the JMX interface. A JRE vulnerability (CVE-2019-2684) 
enables this issue to be exploited remotely. The highest threat from this vulnerability is to data confidentiality and 
integrity as well as system availability.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.apache.org/thread.html/r1fd117082b992e7d43c1286e966c285f98aa362e685695d999ff42f7@%3Cuser.cassandra.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6f77f3e");
  # https://lists.apache.org/thread.html/r718e01f61b35409a4f7a3ccbc1cb5136a1558a9f9c2cb8d4ca9be1ce@%3Cuser.cassandra.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c86aa48e");
  # https://lists.apache.org/thread.html/rab8d90d28f944d84e4d7852f355a25c89451ae02c2decc4d355a9cfc@%3Cuser.cassandra.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6e6f046");
  # https://lists.apache.org/thread.html/rcd7544b24d8fc32b7950ec4c117052410b661babaa857fb1fc641152%40%3Cuser.cassandra.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d880781f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Cassandra version 2.1.22, 2.2.18, 3.0.22, 3.11.8 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(668);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:cassandra");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_cassandra_remote_detection.nbin", "apache_cassandra_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Cassandra");

  exit(0);
}

include('vcf.inc');

app = 'Apache Cassandra';

get_install_count(app_name:app, exit_if_zero:TRUE);

app_info = vcf::combined_get_app_info(app:app);

constraints =
[
  { 'min_version' : '0.0.0', 'fixed_version' : '2.1.22' },
  { 'min_version' : '2.2.0', 'fixed_version' : '2.2.18' },
  { 'min_version' : '3.0.0', 'fixed_version' : '3.0.22' },
  { 'min_version' : '3.11.0', 'fixed_version' : '3.11.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
