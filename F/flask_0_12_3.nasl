#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119778);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/16");

  script_cve_id("CVE-2018-1000656");

  script_name(english:"Flask < 0.12.3 Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web development framework on the remote host is affected by
a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Pallets Flask on the remote host is prior to 0.12.3.
It is, therefore, affected by a denial of service vulnerability in
the JSON decoding process due to improper input validation. An
unauthenticated attacker can exploit this issue by providing JSON
data in a non-text related encoding, which could result in unexpected
memory use.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/pallets/flask/releases/tag/0.12.3");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2018-1000656");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Flask version 0.12.3 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000656");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:python-flask:-");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_flask_installed_nix.nbin");
  script_require_keys("installed_sw/python-flask");

  exit(0);
}

include('misc_func.inc');
include('vcf.inc');

var app_name = 'python-flask';
var app = vcf::get_app_info(app:app_name);

var constraints = [{'fixed_version' : '0.12.3'}];

# Ubuntu has backported patches, using version format like 0.12.2-3
# Currently no VCF version parsing for this, so only fire if paranoid
var ubuntu_release = get_kb_item('Host/Ubuntu/release');

if (!empty_or_null(ubuntu_release) && app['Managed'] && report_paranoia != 2)
{
  if (ubuntu_release =~ "^1[8|6|4].04" )
    audit(AUDIT_POTENTIAL_VULN, app_name);
}

# RHEL has backported the fix so use 0.10.1 in this case
var release = get_kb_item('Host/RedHat/release');
if (isnull(release))
  release = get_kb_item('Host/CentOS/release');
if (('Red Hat' >< release || 'CentOS' >< release) && app['Managed'])
  constraints = [{'fixed_version' : '0.10.1'}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
