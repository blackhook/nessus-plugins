##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145063);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_cve_id("CVE-2016-0260");

  script_name(english:"IBM MQ 8.0 <= 8.0.0.4 (281083)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by a vulnerability. Memory leak in queue-manager
agents in IBM WebSphere MQ 8.x before 8.0.0.5 allows remote attackers to cause a denial of service (heap memory
consumption) by triggering many errors.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/281083");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 8.0.0.5 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0260");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_mq_nix_installed.nbin", "websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'IBM WebSphere MQ');

if (app_info['Type'] != 'Server')
  audit(AUDIT_HOST_NOT, 'an affected product');

constraints = [ { 'min_version' : '8.0', 'max_version' : '8.0.0.4', 'fixed_display' : '8.0.0.5'} ];


vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
