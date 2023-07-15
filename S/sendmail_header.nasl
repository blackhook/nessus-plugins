#
# (C) Tenable Network Security, Inc.
# Original script by Michael Scheidell SECNAP Network Security
#
# Changes by Tenable:
# - Revised plugin titles, output formatting, remove unrelated VDB refs, remove invalid see also link (9/14/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)
# - Update dependencies (7/23/2018)
# - rewritten by Tenable (7/24/2018)

include("compat.inc");

if (description)
{
 script_id(11316);
 script_version("1.44");
 script_cvs_date("Date: 2018/09/17 21:46:53");

 script_cve_id("CVE-2002-1337");
 script_bugtraq_id(6991);
  script_xref(name:"CERT-CC", value:"CA-2003-07");
  script_xref(name:"CERT", value:"398025");

 script_name(english:"Sendmail headers.c crackaddr Function Address Field Handling Remote Overflow");
 script_summary(english:"Checks the version number");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Sendmail server, according to its version number, may be
affected by a remote buffer overflow allowing remote users to gain
root privileges. 

Sendmail versions from 5.79 to 8.12.7 are affected.

*** Nessus reports this vulnerability using only
*** the banner of the remote SMTP server. Therefore,
*** this might be a false positive.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sendmail version 8.12.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2002-1337");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://www.sendmail.org/patchcr.html");


  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Sendmail");

constraints = [{ "min_version" : "5.79", "fixed_version" : "8.12.8" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
