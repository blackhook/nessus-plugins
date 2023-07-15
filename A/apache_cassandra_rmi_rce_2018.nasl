##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143419);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/03");

  script_cve_id("CVE-2018-8016");

  script_name(english:"Apache Cassandra 3.8.x < 3.11.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A database running on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The default configuration in Apache Cassandra 3.8 through 3.11.1 binds an unauthenticated JMX/RMI interface to all 
network interfaces, which allows remote attackers to execute arbitrary Java code via an RMI request.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.apache.org/thread.html/bafb9060bbdf958a1c15ba66c68531116fba4a83858a2796254da066@%3Cuser.cassandra.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cdeea1b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Cassandra version 3.11.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8016");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(306);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/28");
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
  { 'min_version' : '3.8.0', 'max_version' : '3.11.1', 'fixed_display' : '3.11.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
