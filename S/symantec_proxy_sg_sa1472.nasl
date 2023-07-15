#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128329);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2018-18370", "CVE-2018-18371");
  script_xref(name:"IAVA", value:"2019-A-0311");

  script_name(english:"Symantec ProxySG 6.5 < 6.5.10.15 / 6.6 < 6.7.4.2 XSS and Information Disclosure Vulnerabilities (SA1472)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The self-reported SGOS version installed on the remote Symantec
ProxySG device is 6.5.x prior to 6.5.10.15 or 6.6.x prior to 6.7.4.2. It is, 
therefore, affected by the following vulnerabilities:

  - A cross-site scripting (XSS) vulnerability in ProxySG FTP proxy WebFTP mode.
  An authenticated, remote attacker can exploit this, by injecting malicious JavaScript
  code in ProxySG's web listing of a remote FTP server. (CVE-2018-18370)

  - An information disclosure vulnerability exists in ProxySG FTP proxy WebFTP mode.
  An authenticated, remote attacker can exploit this, via intercepting FTP connections
  where a user accesses an FTP server, to obtain plaintext authentication credentials. (CVE-2018-18371)");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/us/en/article.symsa1472.html");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/us/en/article.prod1629.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec ProxySG SGOS version 6.5.10.15, 6.7.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18370");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-18371");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:symantec:proxysg");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::proxysg::get_app_info();

vcf::check_granularity(app_info:app_info, sig_segments:4);
constraints = [
  { 'min_version' : '6.5', 'fixed_version' : '6.5.10.15' },
  { 'min_version' : '6.6', 'fixed_version' : '6.7.4.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
