#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{ 
  script_id(125633);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2017-5647", "CVE-2017-5664");
  script_bugtraq_id(98888);

  script_name(english:"Symantec Content Analysis < 2.3.5.1 affected by Multiple Vulnerabilities (SYMSA1419)");
  script_summary(english:"Checks the version of Symantec Content Analysis");

  script_set_attribute(attribute:"synopsis", value:
  "The remote host is running a version of Symantec Content Analysis that is
  affected by Multiple Vulnerabilities");
    script_set_attribute(attribute:"description", value:
  "The version of Symantec Content Analysis running on the
  remote host is prior to version 2.3.5.1. It is, therefore,
  affected by multiple vulnerabilities:

    - A bug in the handling of the pipelined requests in
      Apache Tomcat 9.0.0.M1 to 9.0.0.M18, 8.5.0 to 8.5.12,
      8.0.0.RC1 to 8.0.42, 7.0.0 to 7.0.76, and 6.0.0 to
      6.0.52, when send file was used, results in the
      pipelined request being lost when send file processing
      of the previous request completed. This could result
      in responses appearing to be sent for the wrong
      request. (CVE-2017-5647)

    - The error page mechanism of the Java Servlet
      Specification requires that, when an error occurs
      and an error page is configured for the error that
      occurred, the original request and response are
      forwarded to the error page. This means that the
      request is presented to the error page with the
      original HTTP method. If the error page is a
      static file, expected behaviour is to serve
      content of the file as if processing a GET
      request, regardless of the actual HTTP method.
      (CVE-2017-5664)");
    # https://support.symantec.com/en_US/article.SYMSA1419.html
    script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de884b8");
    script_set_attribute(attribute:"solution", value:
  "Refer to vendor advisory (Symantec SYMSA1419) for suggested
  workaround, or upgrade to an unaffected version.");
    script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
    script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
    script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
    script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
    script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5664");
    script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

    script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/06");
    script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
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
  {'min_version': '1.3', 'max_version': '1.4', 'fixed_display': 'Refer to vendor advisory.' },
  {'min_version': '2.1', 'max_version': '2.2', 'fixed_display': 'Refer to vendor advisory.' },
  {'min_version': '2.2', 'max_version': '2.3', 'fixed_display': 'Refer to vendor advisory.' },
  {'min_version': '2.3', 'fixed_version' : '2.3.5.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
