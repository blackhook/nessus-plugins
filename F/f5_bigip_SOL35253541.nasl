#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K35253541.
#
# @NOAGENT@
##

include('compat.inc');

if (description)
{
  script_id(168419);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2020-14779",
    "CVE-2020-14781",
    "CVE-2020-14782",
    "CVE-2020-14797"
  );

  script_name(english:"F5 Networks BIG-IP : Java vulnerabilities (K35253541)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of F5 Networks BIG-IP installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the K35253541 advisory.

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Serialization).
    Supported versions that are affected are Java SE: 7u271, 8u261, 11.0.8 and 15; Java SE Embedded: 8u261.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: Applies to client and server deployment of Java. This vulnerability can be exploited through
    sandboxed Java Web Start applications and sandboxed Java applets. It can also be exploited by supplying
    data to APIs in the specified Component without using sandboxed Java Web Start applications or sandboxed
    Java applets, such as through a web service. (CVE-2020-14779)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: JNDI). Supported
    versions that are affected are Java SE: 7u271, 8u261, 11.0.8 and 15; Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    read access to a subset of Java SE, Java SE Embedded accessible data. Note: Applies to client and server
    deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start applications and
    sandboxed Java applets. It can also be exploited by supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or sandboxed Java applets, such as through a web
    service. (CVE-2020-14781)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Libraries). Supported
    versions that are affected are Java SE: 7u271, 8u261, 11.0.8 and 15; Java SE Embedded: 8u261. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Java SE, Java SE Embedded accessible data. Note: Applies to
    client and server deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start
    applications and sandboxed Java applets. It can also be exploited by supplying data to APIs in the
    specified Component without using sandboxed Java Web Start applications or sandboxed Java applets, such as
    through a web service. (CVE-2020-14782, CVE-2020-14797)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K35253541");
  script_set_attribute(attribute:"solution", value:
"Upgrade to one of the non-vulnerable versions listed in the F5 Solution K35253541.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14797");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_domain_name_system");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_wan_optimization_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip_protocol_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var sol = 'K35253541';
var vmatrix = {
  'AFM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'APM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'ASM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'DNS': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'GTM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'LTM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'PEM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'PSM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  },
  'WOM': {
    'affected': [
      '17.0.0','16.1.0-16.1.3','15.1.0-15.1.8','14.1.0-14.1.5','13.1.0-13.1.5'
    ],
  }
};

if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  var extra = NULL;
  if (report_verbosity > 0) extra = bigip_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
