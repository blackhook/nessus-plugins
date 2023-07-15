#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103508);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-7079");
  script_bugtraq_id(100983);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-09-25-7");

  script_name(english:"iTunes < 12.7 Data Sync Vulnerability (Mac OS)");
  script_summary(english:"Checks iTunes version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by an
insecure permissions vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of iTunes installed on the remote Mac OS X host is older
than 12.7. It is, therefore, affected by a data sync
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208140");
  script_set_attribute(attribute:"solution", value:
"Upgrade to iTunes 12.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7079");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_itunes_detect.nasl");
  script_require_keys("Host/MacOSX/Version", "installed_sw/iTunes");

  exit(0);
}

include("vcf.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app_info = vcf::get_app_info(app:"iTunes");

constraints = [{"fixed_version" : "12.7"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
