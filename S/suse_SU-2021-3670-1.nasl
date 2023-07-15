#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3670-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155466);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-30640", "CVE-2021-33037", "CVE-2021-41079");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3670-1");
  script_xref(name:"IAVA", value:"2021-A-0303-S");

  script_name(english:"SUSE SLES15 Security Update : tomcat (SUSE-SU-2021:3670-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3670-1 advisory.

  - A vulnerability in the JNDI Realm of Apache Tomcat allows an attacker to authenticate using variations of
    a valid user name and/or to bypass some of the protection provided by the LockOut Realm. This issue
    affects Apache Tomcat 10.0.0-M1 to 10.0.5; 9.0.0.M1 to 9.0.45; 8.5.0 to 8.5.65. (CVE-2021-30640)

  - Apache Tomcat 10.0.0-M1 to 10.0.6, 9.0.0.M1 to 9.0.46 and 8.5.0 to 8.5.66 did not correctly parse the HTTP
    transfer-encoding request header in some circumstances leading to the possibility to request smuggling
    when used with a reverse proxy. Specifically: - Tomcat incorrectly ignored the transfer encoding header if
    the client declared it would only accept an HTTP/1.0 response; - Tomcat honoured the identify encoding;
    and - Tomcat did not ensure that, if present, the chunked encoding was the final encoding.
    (CVE-2021-33037)

  - Apache Tomcat 8.5.0 to 8.5.63, 9.0.0-M1 to 9.0.43 and 10.0.0-M1 to 10.0.2 did not properly validate
    incoming TLS packets. When Tomcat was configured to use NIO+OpenSSL or NIO2+OpenSSL for TLS, a specially
    crafted packet could be used to trigger an infinite loop resulting in a denial of service.
    (CVE-2021-41079)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190558");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-November/009730.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac5a9b79");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41079");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-el-3_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-jsp-2_3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-servlet-4_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'tomcat-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'tomcat-admin-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'tomcat-el-3_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'tomcat-jsp-2_3-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'tomcat-lib-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'tomcat-servlet-4_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'tomcat-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-15'},
    {'reference':'tomcat-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-admin-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-admin-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-el-3_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-el-3_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-jsp-2_3-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-jsp-2_3-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-lib-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-lib-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-servlet-4_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-servlet-4_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-ESPOS-release-15'},
    {'reference':'tomcat-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-admin-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-admin-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-el-3_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-el-3_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-jsp-2_3-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-jsp-2_3-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-lib-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-lib-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-servlet-4_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-servlet-4_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_HPC-LTSS-release-15'},
    {'reference':'tomcat-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'tomcat-admin-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'tomcat-el-3_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'tomcat-jsp-2_3-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'tomcat-lib-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'tomcat-servlet-4_0-api-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'},
    {'reference':'tomcat-webapps-9.0.36-3.84.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-ltss-release-15'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tomcat / tomcat-admin-webapps / tomcat-el-3_0-api / tomcat-jsp-2_3-api / etc');
}
