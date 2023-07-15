#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140401);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-11254");

  script_name(english:"Kubernetes < 1.15.10 / 1.16.x < 1.16.7 / 1.17.x < 1.17.3 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Kubernetes installed on the remote host is a version prior to 1.13.10, or 1.14.x prior to 1.14.6, or
1.15.x prior to 1.15.3. It is, therefore, affected by a denial of service vulnerability

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://discuss.kubernetes.io/t/security-advisory-cve-2019-11254-denial-of-service-vulnerability-from-malicious-yaml-payloads/10345
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f99cd3c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kubernetes 1.15.10, 1.16.7, 1.17.3 or later, please refer to the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kubernetes:kubernetes");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:kubernetes");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kube_detect.nbin");
  script_require_keys("installed_sw/Kubernetes");

  exit(0);
}

include('vcf.inc');

app_name = 'Kubernetes';
app_info = vcf::get_app_info(app:app_name);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '1.0.0', 'fixed_version' : '1.15.10' },
  { 'min_version' : '1.16.0', 'fixed_version' : '1.16.7' },
  { 'min_version' : '1.17.0', 'fixed_version' : '1.17.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

