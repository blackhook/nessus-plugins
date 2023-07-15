#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108889);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-1232", "CVE-2018-1233", "CVE-2018-1234");
  script_xref(name:"IAVA", value:"2018-A-0101");

  script_name(english:"RSA Authentication Agent for Web for IIS 8.x < 8.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of RSA Authentication Agent for Web for IIS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an authentication agent installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of RSA Authentication Agent for Web for IIS is 8.x prior
to 8.0.2. It is, therefore, affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2018/Mar/60");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RSA Authentication Agent for Web for IIS 8.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_authentication_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rsa_authentication_agent_for_web_iis.nbin");
  script_require_keys("SMB/RSA Authentication Agent for Web for IIS/Path", "SMB/RSA Authentication Agent for Web for IIS/Version");

  exit(0);
}

include("vcf.inc");

app = "RSA Authentication Agent for Web for IIS";

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "8.0", "fixed_version" : "8.0.2" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
