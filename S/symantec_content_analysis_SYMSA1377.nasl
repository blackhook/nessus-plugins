#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{ 
  script_id(125636);
  script_version("1.4");
  script_cvs_date("Date: 2019/07/01 11:41:24");

  script_cve_id("CVE-2016-4483");
  script_bugtraq_id(90013);

  script_name(english:"Symantec Content Analysis 2.3 < 2.3.1.1 affected by Multiple Vulnerabilities (SYMSA1377)");
  script_summary(english:"Checks the version of Symantec Content Analysis");

  script_set_attribute(attribute:"synopsis", value:
  "The remote host is running a version of Symantec Content Analysis that is
  affected by Multiple Vulnerabilities");
    script_set_attribute(attribute:"description", value:
  "The version of Symantec Content Analysis running on the
  remote host is prior to version 2.3.1.1. It is, therefore,
  affected by a vulnerability in the xmlBufAttrSerializeTxtContent
  function in xmlsave.c in libxml2 allows context-dependent
  attackers to cause a denial of service (out-of-bounds read and
  application crash) via a non-UTF-8 attribute value, related
  to serialization.");
    # https://support.symantec.com/en_US/article.SYMSA1377.html
    script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1553e4eb");
    script_set_attribute(attribute:"solution", value:
  "Refer to vendor advisory (Symantec SYMSA1377) for suggested
  workaround, or upgrade to an unaffected version.");
    script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
    script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
    script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
    script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
    script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4483");
    script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
    script_set_attribute(attribute:"exploit_available", value:"true");

    script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/06");
    script_set_attribute(attribute:"patch_publication_date", value:"2017/07/20");
    script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");

    script_set_attribute(attribute:"plugin_type", value:"local");
    script_set_attribute(attribute:"cpe", value:"x-cpe:/h:symantec:content_analysis");
    script_set_attribute(attribute:"cpe", value:"x-cpe:/h:bluecoat:content_analysis");
    script_end_attributes();

    script_category(ACT_GATHER_INFO);
    script_family(english:"Misc.");

    script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

    script_dependencies("symantec_content_analysis_local_detect.nbin");
    script_require_keys("installed_sw/Symantec Content Analysis");

    exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('vcf.inc');

app_name = 'Symantec Content Analysis';

app_info = vcf::get_app_info(app:app_name, port:0);

constraints = [{'min_version': '2.3', 'fixed_version' : '2.3.1.1'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
