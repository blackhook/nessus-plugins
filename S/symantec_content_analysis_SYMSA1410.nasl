#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{ 
  script_id(125637);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2017-3169", "CVE-2017-7679");
  script_bugtraq_id(99170, 99134);

  script_name(english:"Symantec Content Analysis < 2.3.1.1 affected by Multiple Vulnerabilities (SYMSA1410)");
  script_summary(english:"Checks the version of Symantec Content Analysis");

  script_set_attribute(attribute:"synopsis", value:
  "The remote host is running a version of Symantec Content Analysis that is
  affected by Multiple Vulnerabilities");
    script_set_attribute(attribute:"description", value:
  "The version of Symantec Content Analysis running on the
  remote host is prior to version 2.3.1.1. It is, therefore,
  affected by multiple vulnerabilities:

    - A vulnerability in Apache httpd 2.2.x before 2.2.33
      and 2.4.x before 2.4.26, mod_mime can read one byte
      past the end of a buffer when sending a malicious
      Content-Type response header. (CVE-2017-7679)

    - A vulnerability in Apache httpd 2.2.x before 2.2.33
      and 2.4.x before 2.4.26, mod_ssl may dereference a
      NULL pointer when third-party modules call
      ap_hook_process_connection() during an HTTP request
      to an HTTPS port. (CVE-2017-3169)");
    # https://support.symantec.com/en_US/article.SYMSA1410.html
    script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db8511d5");
    script_set_attribute(attribute:"solution", value:
  "Refer to vendor advisory (Symantec SYMSA1410) for suggested
  workaround, or upgrade to an unaffected version.");
    script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
    script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
    script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7679");
    script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

constraints = [
  {'min_version': '2.2', 'max_version': '2.3', 'fixed_display': 'Refer to vendor advisory.' },
  {'min_version': '2.3', 'fixed_version' : '2.3.1.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
