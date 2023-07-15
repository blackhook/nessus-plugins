#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107267);
  script_version("1.5");
  script_cvs_date("Date: 2018/07/27 18:38:15");

  script_cve_id("CVE-2018-0489");
  script_bugtraq_id(103172);
  script_xref(name:"IAVB", value:"2018-B-0038");

  script_name(english:"Shibboleth 2.0 < 2.6 XMLTooling-C DTD Processing Forgery Vulnerability");
  script_summary(english:"Checks for the product and version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a single-sign-on service provider installed which is
vulnerable to a user attribute forgery issue.");
  script_set_attribute(attribute:"description", value:
"The version of Shibboleth Service Provider installed on the remote
host is version 2.0 prior to 2.6. As a result it is affected
by a user attribute forgery issue which could allow an attacker
to impersonate a valid user and gain access to sensitive information.

Note: Though versions higher than 2.6 are not vulnerable, 2.6.1.4 
contains a patch for the affected library (XMLTooling-C) and is 
recommended by the vendor.");
  # https://shibboleth.net/community/advisories/secadv_20180112.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9abdea7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Shibboleth Service Provider version 2.6.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:shibboleth:service_provider");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

  script_dependencies("shibboleth_sp_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Shibboleth Service Provider");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");
include("vcf_extras.inc");

app = vcf::get_app_info(app:"Shibboleth Service Provider");

constraints = [{"min_version":"2.0", "fixed_version" : "2.6", "fixed_display":"2.6.1.4"}];
vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
