#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125387);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/30 13:24:47");

  script_cve_id("CVE-2018-11803");
  script_bugtraq_id(106770);

  script_name(english:"Apache Subversion 1.10.x < 1.10.4 / 1.11.x < 1.11.1 mod_dav_svn DoS");
  script_summary(english:"Checks Subversion Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Subversion Server is 1.10.x prior to 1.10.4 or 1.11.x prior to 1.11.1 and is, therefore,
affected by a denial of service (DoS) vulnerability. A flaw exists in the implementation of mod_dav_svn due to failing
to validate the root path of the directory listing provided by the client. An unauthenticated, remote attacker can
exploit this issue, to cause the process to stop responding.");
  script_set_attribute(attribute:"see_also", value:"https://subversion.apache.org/security/CVE-2018-11803-advisory.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Subversion Server 1.10.4, 1.11.1 or later, or apply the vendor-supplied patch or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11803");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Windows");

  script_dependencies("subversion_installed.nasl");
  script_require_keys("installed_sw/Subversion Server", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::get_app_info(app:"Subversion Server");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { "min_version" : "1.10.0", "fixed_version" : "1.10.4" },
  { "min_version" : "1.11.0", "fixed_version" : "1.11.1" }
];

vcf::apache_subversion::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
