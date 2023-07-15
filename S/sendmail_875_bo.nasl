#
# (C) Tenable Network Security, Inc.
# Original script by Xue Yong Zhi <xueyong@udel.edu>
#
# Changes by Tenable:
# - Revised plugin title, desc/solution enhancement, output formattings (9/14/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)
# - rewritten by Tenable (7/13/2018)

include("compat.inc");

if (description)
{
  script_id(11347);
  script_version("1.18");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-1999-0131");
  script_bugtraq_id(717);

  script_name(english:"Sendmail < 8.7.6 Multiple Local Vulnerabilities");
  script_summary(english:"Checks the version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by
multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The remote Sendmail server, according to its version number,
has a buffer overflow and denial of service problem. Using
a flaw in the GECOS field handling, it may allow a local
user to gain root access.");
  script_set_attribute(attribute:"solution", value:
"Install Sendmail 8.7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0131");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"1996/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/11");

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

constraints = [{ "fixed_version" : "8.7.6" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
