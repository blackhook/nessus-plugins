##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143420);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/03");

  script_cve_id("CVE-2015-0225");
  script_bugtraq_id(73478);

  script_name(english:"Apache Cassandra 1.2.x <= 1.2.19 / 2.0.x <= 2.0.13 / 2.1.x <= 2.1.3 RCE");

  script_set_attribute(attribute:"synopsis", value:
"A database running on the remote host is affected by a remote code execution vulnerability .");
  script_set_attribute(attribute:"description", value:
"The default configuration in Apache Cassandra running on the remote host version 1.2.0 through 1.2.19, 2.0.0 through 
2.0.13, and 2.1.0 through 2.1.3 bound an unauthenticated JMX/RMI interface to all network interfaces. A remote attacker 
able to access the RMI, an API for the transport and remote execution of serialized Java, could use this flaw to 
execute arbitrary code as the user running Cassandra.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://packetstormsecurity.com/files/131249/Apache-Cassandra-Remote-Code-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97b7ae44");
  # https://www.mail-archive.com/user@cassandra.apache.org/msg41819.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?311e0da4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Apache Cassandra, refer to the vendor advisory for relevant patch and configuration
settings.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/03");
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
  { 'min_version' : '1.2.0', 'max_version' : '1.2.19', 'fixed_display' : 'Refer to vendor advisory.' },
  { 'min_version' : '2.0.0', 'max_version' : '2.0.13', 'fixed_display' : '2.0.14'},
  { 'min_version' : '2.1.0', 'max_version' : '2.1.3', 'fixed_display' : '2.1.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
