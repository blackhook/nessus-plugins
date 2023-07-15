##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162136);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-9485",
    "CVE-2020-11978",
    "CVE-2020-11981",
    "CVE-2020-11982",
    "CVE-2020-11983",
    "CVE-2020-13927"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");

  script_name(english:"Apache Airflow < 1.10.11 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is missing a vendor-supplied update.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Airflow is prior to 1.10.11. It is, therefore, affected by multiple vulnerabilities, including
the following:

  - An issue was found in Apache Airflow versions 1.10.10 and below. When using CeleryExecutor, if an attacker
    can connect to the broker (Redis, RabbitMQ) directly, it is possible to inject commands, resulting in the
    celery worker running arbitrary commands. (CVE-2020-11981)

  - An issue was found in Apache Airflow versions 1.10.10 and below. When using CeleryExecutor, if an attack
    can connect to the broker (Redis, RabbitMQ) directly, it was possible to insert a malicious payload
    directly to the broker which could lead to a deserialization attack (and thus remote code execution) on
    the Worker. (CVE-2020-11982)

  - An issue was found in Apache Airflow versions 1.10.10 and below. A remote code/command injection
    vulnerability was discovered in one of the example DAGs shipped with Airflow which would allow any
    authenticated user to run arbitrary commands as the user running airflow worker/scheduler (depending on
    the executor in use). If you already have examples disabled by setting load_examples=False in the config
    then you are not vulnerable. (CVE-2020-11978)

  - The previous default setting for Airflow's Experimental API was to allow all API requests without
    authentication, but this poses security risks to users who miss this fact. From Airflow 1.10.11 the
    default has been changed to deny all requests by default and is documented at
    https://airflow.apache.org/docs/1.10.11/security.html#api-authentication. Note this change fixes it for
    new installs but existing users need to change their config to default
    [api]auth_backend = airflow.api.auth.backend.deny_all as mentioned in the Updating Guide:
    https://github.com/apache/airflow/blob/1.10.11/UPDATING.md#experimental-api-will-deny-all-request-by-default
    (CVE-2020-13927)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/cn57zwylxsnzjyjztwqxpmly0x9q5ljx");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/mq1bpqf3ztg1nhyc5qbrjobfrzttwx1d");
  # https://airflow.apache.org/docs/apache-airflow/2.3.1/release_notes.html#airflow-1-10-11-2020-07-10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?152f8770");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Airflow version 1.10.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13927");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:airflow");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_airflow_web_api_detect.nbin");
  script_require_keys("installed_sw/Apache Airflow");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:8080);
var app_info = vcf::get_app_info(app:'Apache Airflow', port:port, webapp:TRUE);
var constraints = [{ 'fixed_version': '1.10.11'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE}
);
