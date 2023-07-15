#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100594);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3126");
  script_bugtraq_id(98557);

  script_name(english:"Fortinet FortiAnalyzer / FortiManager 5.4.x < 5.4.3 Open Redirect (FG-IR-17-014)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site redirection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FortiAnalyzer or FortiManager running on the remote
device is 5.4.x prior to 5.4.3. It is, therefore, affected by a
cross-site redirection vulnerability in its web-based user interface
due to improper validation of input before returning it to users. An
unauthenticated, remote attacker can exploit this, via a specially
crafted link, to redirect an unsuspecting user to an arbitrary website
of the attacker's choosing.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-17-014");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiAnalyzer or FortiManager version 5.4.3 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3126");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortianalyzer_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortimanager_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("vcf.inc");

name = "FortiAnalyzer / FortiManager";
# Using kb source to grab the model to check for FortiAnalyzer / FortiManager
app_info = vcf::get_app_info(app:"FortiAnalyzer",
                              kb_ver:"Host/Fortigate/version",
                              kb_source:"Host/Fortigate/model",
                              webapp:true);

if( "FortiAnalyzer" >!< app_info.source )
{
  if ( "FortiManager" >!< app_info.source )
      audit(AUDIT_HOST_NOT, "a " + name + " device");
  else
    app_info.app = "FortiManager";
}

constraints = [
  { "min_version" : "5.4.0", "fixed_version" : "5.4.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
