#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117341);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/04");

  script_cve_id("CVE-2018-13819", "CVE-2018-13820", "CVE-2018-13821");
  script_bugtraq_id(105199);
  script_xref(name:"IAVB", value:"2018-B-0122-S");

  script_name(english:"CA Unified Infrastructure Management < 8.48 / 8.53 Multiple Vulnerabilities (CA20180829-02)");
  script_summary(english:"Checks the CA UIM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number from the CA Unified
Infrastructure Management (UIM) application running on the remote host
is prior to 8.48 or 8.53. It is, therefore, affected by multiple
vulnerabilities :

  - A hardcoded secret key exists that could allow
    information disclosure. (CVE-2018-13819)

  - A hardcoded passphrase exists that could allow
    information disclosure. (CVE-2018-13820)

  - An unspecified authentication error exists that
    could allow various actions including reading
    and writing files. (CVE-2018-13821)

Note: The version was determined by checking the Unified Management
      Portal instance running on this host; however, it may not
      directly reflect the version of the Unified Infrastructure
      Management instance.");
  # https://support.ca.com/us/product-content/recommended-reading/security-notices/ca20180829-02--security-notice-for-ca-unified-infrastructure-mgt.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?259d5fdc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CA UIM version 8.48 or 8.53 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13821");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ca:unified_infrastructure_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ca_ump_detect.nbin");
  script_require_keys("installed_sw/CA UMP", "Settings/ParanoidReport");

  exit(0);
}

include("http.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product = "CA Unified Infrastructure Management";

# Contains the version info we try to use
ump = "CA UMP";

port = get_http_port(default:80);
app_info = vcf::get_app_info(app:ump, port:80, webapp:TRUE);

constraints = [
  { "min_version" : "0", "max_version" : "8.4.7.999999", "fixed_version" : "8.4.8" },
  { "min_version" : "8.5", "fixed_version" : "8.5.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
