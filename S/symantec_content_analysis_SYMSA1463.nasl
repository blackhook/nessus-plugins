#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125550);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id(
    "CVE-2018-1336",
    "CVE-2018-8019",
    "CVE-2018-8020",
    "CVE-2018-8034"
  );
  script_bugtraq_id(
    104895,
    104898,
    104934,
    104936
  );

  script_name(english:"Symantec Content Analysis < 2.3.5.1 affected by Multiple Vulnerabilities (SYMSA1463)");
  script_summary(english:"Checks the version of Symantec Content Analysis");

  script_set_attribute(attribute:"synopsis", value:
  "The remote host is running a version of Symantec Content Analysis that is
  affected by Multiple Vulnerabilities");
    script_set_attribute(attribute:"description", value:
  "The version of Symantec Content Analysis running on the
  remote host is prior to version 2.3.5.1. It is, therefore,
  affected by multiple vulnerabilities:
    - An improper handing of overflow in the UTF-8 decoder
      with supplementary characters can lead to an infinite
      loop in the decoder causing a Denial of Service.
      (CVE-2018-1336)

    - When using an OCSP responder Apache Tomcat Native
      1.2.0 to 1.2.16 and 1.1.23 to 1.1.34 did not correctly
      handle invalid responses. This allowed for revoked client
      certificates to be incorrectly identified. It was therefore
      possible for users to authenticate with revoked certificates
      when using mutual TLS.(CVE-2018-8019)
      
    - Apache Tomcat Native 1.2.0 to 1.2.16 and 1.1.23 to 1.1.34 has
      a flaw that does not properly check OCSP pre-produced responses,
      which are lists (multiple entries) of certificate statuses.
      (CVE-2018-8020)

    - The host name verification when using TLS with the
      WebSocket client was missing. It is now enabled by
      default. (CVE-2018-8034)

    ");
    # https://support.symantec.com/en_US/article.SYMSA1463.html
    script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.SYMSA1463.html");
    script_set_attribute(attribute:"solution", value:
  "Refer to vendor advisory (Symantec SYMSA1463) for suggested
  workaround, or upgrade to an unaffected version.");
    script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
    script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
    script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
    script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
    script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8034");
    script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  
    script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/22");
    script_set_attribute(attribute:"patch_publication_date", value:"2018/10/11");
    script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/30");
  
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
  {'min_version': '2.3', 'fixed_version' : '2.3.5.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

