#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103836);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-13679", "CVE-2017-13682");
  script_bugtraq_id(101090, 101497);
  script_xref(name:"IAVB", value:"2017-B-0140");

  script_name(english:"Symantec Encryption Desktop 10.x =< 10.4.1 MP2HF1 (SYM17-010)");
  script_summary(english:"Checks the Symantec Encryption Desktop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a data encryption application installed that is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Encryption Desktop installed on the remote
host is version 10.x prior to or equal to 10.4.1 MP2 hot fix 1. It is,
therefore, affected by an unspecified denial of service and kernel
memory leak vulnerability.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20171009_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6dfa557");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Encryption Desktop 10.4.1 MP2HF1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:encryption_desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:pgp_desktop");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_symantec_encryption_desktop_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "Host/local_checks_enabled", "installed_sw/Symantec Encryption Desktop");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("vcf.inc");

app_info = vcf::get_app_info(app:"Symantec Encryption Desktop");

# MP2 HF1 is build 777
constraints = [ { "min_version" : "10.0", "fixed_version" : "10.4.1.777" } ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE); 
