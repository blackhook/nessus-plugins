#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124590);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id("CVE-2017-1002101", "CVE-2017-1002102");

  script_name(english:"Kubernetes 1.3.x < 1.7.14 / 1.8.x < 1.8.9 / 1.9.x < 1.9.4 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application affected by multiple vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Kubernetes installed on the remote host is version 1.3.x prior to 1.7.14, 1.8.x prior to 1.8.9 or 1.9.x
prior to 1.9.4. It is, therefore, affected by multiple vulnerabilities.

  - An arbitrary file access vulnerability exists in containers using subpath volume mounts. An authenticated, local
    attacker can exploit this to access arbitrary files or directories including the host's filesystem.
    (CVE-2017-1002101)

  - An arbitrary file deletion vulnerability exists in containers using a secret, configMap, projected or downwardAPI
    volume. An unauthenticated, local attacker can exploit this to delete arbitrary files or directories from the nodes
    where they are running. (CVE-2017-1002102)");
  # https://groups.google.com/forum/#!topic/kubernetes-security-announce/P7lBjbjDKd8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7000232d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kubernetes 1.7.14, 1.8.9, 1.9.4 or later, please refer to the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1002102");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-1002101");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kubernetes:kubernetes");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:kubernetes");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kube_detect.nbin");
  script_require_keys("installed_sw/Kubernetes");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('vcf.inc');

app_name = 'Kubernetes';
app_info = vcf::get_app_info(app:app_name);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '1.3.0', 'fixed_version' : '1.7.0', 'fixed_display' : '1.7.14 or 1.8.9 or 1.9.4' },
  { 'min_version' : '1.7.0', 'fixed_version' : '1.7.14' },
  { 'min_version' : '1.8.0', 'fixed_version' : '1.8.9' },
  { 'min_version' : '1.9.0', 'fixed_version' : '1.9.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
