#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109035);
  script_version("1.7");
  script_cvs_date("Date: 2020/01/07");

  script_cve_id("CVE-2016-10258", "CVE-2017-13677", "CVE-2017-13678");
  script_bugtraq_id(103685);

  script_name(english:"Symantec ProxySG 6.5 < 6.5.10.8 / 6.6 < 6.6.5.14 / 6.7.3 < 6.7.3.7 / 6.7.4 < 6.7.4.1 Multiple Vulnerabilities (SA162)");
  script_summary(english:"Checks the Symantec ProxySG SGOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The self-reported SGOS version installed on the remote Symante ProxySG device is 6.5.x prior to 6.5.10.8, 6.6.x prior
to 6.6.5.14, 6.7.3.x prior to 6.7.3.7, or 6.7.4.x prior to 6.7.4.1. It is, therefore, affected by multiple
vulnerabilities:

  - An unrestricted file upload vulnerability exists in the ASG and ProxySG management consoles. A malicious
    appliance administrator can upload arbitrary malicious files to the management console and trick another
    administrator user into downloading and executing malicious code. (CVE-2016-10258)

  - A denial-of-service (DoS) vulnerability in the ASG and ProxySG management consoles. A remote attacker can
    use crafted HTTP/HTTPS requests to cause denial-of-service through management console application crashes.
    (CVE-2017-13677)

  - A stored XSS vulnerability exists the ASG and ProxySG management consoles in that a malicious appliance
    administrator can inject arbitrary JavaScript code in the management console web client application.
    (CVE-2017-13678)");
  # https://www.symantec.com/security-center/network-protection-security-advisories/SA162
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26c3b5a9");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/us/en/article.prod1629.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec ProxySG SGOS version 6.5.10.8 / 6.6.5.14 / 6.7.3.7 / 6.7.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10258");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:symantec:proxysg");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::proxysg::get_app_info();

vcf::check_granularity(app_info:app_info, sig_segments:4);
constraints = [
  { 'min_version' : '6.5', 'fixed_version' : '6.5.10.8' },
  { 'min_version' : '6.6', 'fixed_version' : '6.6.5.14' },
  { 'min_version' : '6.7', 'fixed_version' : '6.7.3.7' },
  { 'min_version' : '6.7.4', 'fixed_version' : '6.7.4.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});