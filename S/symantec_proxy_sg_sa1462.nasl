#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128303);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/07");

  script_cve_id("CVE-2018-0732");
  script_bugtraq_id(104442);

  script_name(english:"Symantec ProxySG 6.5 / 6.6 / 6.7 < 6.7.4.1 OpenSSL Denial of Service Vulnerability (SA1462)");
  script_summary(english:"Checks the Symantec ProxySG SGOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The self-reported SGOS version installed on the remote Symantec
ProxySG device is 6.5.x, 6.6.x or 6.7 prior to 6.7.4.1. It is, 
therefore, affected by OpenSSL denial of service vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/us/en/article.symsa1462.html");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/us/en/article.prod1629.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec ProxySG SGOS version 6.7.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0732");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:symantec:proxysg");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::proxysg::get_app_info();

vcf::check_granularity(app_info:app_info, sig_segments:4);
constraints = [
  { 'min_version' : '6.5.0', 'max_version' : '6.5.9999', 
      'fixed_display' : 'No remediation available at this time, please check with the vendor for possible solutions.' },
  { 'min_version' : '6.6.0', 'fixed_version' : '6.7.4.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
