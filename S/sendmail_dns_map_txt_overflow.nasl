#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11232);
  script_version("1.24");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id("CVE-2002-0906");
  script_bugtraq_id(5122);

  script_name(english:"Sendmail Custom DNS Map TXT Query Overflow");
  script_summary(english:"Check Sendmail version number");

  script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on this host.");
  script_set_attribute(attribute:"description", value:
"The remote Sendmail server, according to its version number, may be 
vulnerable to a buffer overflow in its DNS handling code.

The owner of a malicious name server could use this flaw to cause a
denial of service and possibly to execute arbitrary code on this
host.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sendmail 8.12.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2002-0906");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sendmail:sendmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english: "SMTP problems");

  script_dependencies("sendmail_detect.nbin");
  script_require_keys("installed_sw/Sendmail");
  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"Sendmail");

constraints = [{ "fixed_version" : "8.12.5" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
