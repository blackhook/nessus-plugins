#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K10002140.
#
# @NOAGENT@
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159514);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/05");

  script_cve_id("CVE-2017-7657", "CVE-2017-7658");

  script_name(english:"F5 Networks BIG-IP : Eclipse Jetty vulnerabilities (K10002140)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the K10002140 advisory.

  - In Eclipse Jetty, versions 9.2.x and older, 9.3.x (all configurations), and 9.4.x (non-default
    configuration with RFC2616 compliance enabled), transfer-encoding chunks are handled poorly. The chunk
    length parsing was vulnerable to an integer overflow. Thus a large chunk size could be interpreted as a
    smaller chunk size and content sent as chunk body could be interpreted as a pipelined request. If Jetty
    was deployed behind an intermediary that imposed some authorization and that intermediary allowed
    arbitrarily large chunks to be passed on unchanged, then this flaw could be used to bypass the
    authorization imposed by the intermediary as the fake pipelined request would not be interpreted by the
    intermediary as a request. (CVE-2017-7657)

  - In Eclipse Jetty Server, versions 9.2.x and older, 9.3.x (all non HTTP/1.x configurations), and 9.4.x (all
    HTTP/1.x configurations), when presented with two content-lengths headers, Jetty ignored the second. When
    presented with a content-length and a chunked encoding header, the content-length was ignored (as per RFC
    2616). If an intermediary decided on the shorter length, but still passed on the longer body, then body
    content could be interpreted by Jetty as a pipelined request. If the intermediary was imposing
    authorization, the fake pipelined request would bypass that authorization. (CVE-2017-7658)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K10002140");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K10002140.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7658");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"F5 Networks Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include('f5_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var version = get_kb_item('Host/BIG-IP/version');
if ( ! version ) audit(AUDIT_OS_NOT, 'F5 Networks BIG-IP');
if ( isnull(get_kb_item('Host/BIG-IP/hotfix')) ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/hotfix');
if ( ! get_kb_item('Host/BIG-IP/modules') ) audit(AUDIT_KB_MISSING, 'Host/BIG-IP/modules');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var sol = 'K10002140';
var vmatrix = {
  'AFM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4'
    ],
  },
  'APM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4'
    ],
  },
  'ASM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4'
    ],
  },
  'GTM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4'
    ],
  },
  'LTM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4'
    ],
  },
  'PEM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4'
    ],
  },
  'PSM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4'
    ],
  },
  'WOM': {
    'affected': [
      '16.1.0-16.1.2','15.1.0-15.1.5','14.1.0-14.1.4'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
}
else
{
  var tested = bigip_get_tested_modules();
  var audit_extra = 'For BIG-IP module(s) ' + tested + ',';
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, 'running any of the affected modules');
}
