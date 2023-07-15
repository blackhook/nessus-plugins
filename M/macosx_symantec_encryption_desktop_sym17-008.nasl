#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103251);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-6330");
  script_bugtraq_id(100552);

  script_name(english:"Symantec Encryption Desktop 10.x < 10.4.1 MP2 DoS");
  script_summary(english:"Checks the Symantec Encryption Desktop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a data encryption application installed that is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Encryption Desktop installed on the remote
host is version 10.x prior to 10.4.1 MP2. It is, therefore, affected
by a denial of service vulnerability.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1115b8a5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Encryption Desktop 10.4.1 MP2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6330");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:encryption_desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:pgp_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_symantec_encryption_desktop_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "Host/local_checks_enabled", "installed_sw/Symantec Encryption Desktop");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("vcf.inc");

app_info = vcf::get_app_info(app:"Symantec Encryption Desktop");

# MP2 is build 759
constraints = [ { "min_version" : "10.0", "fixed_version" : "10.4.1.759" } ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING); 
