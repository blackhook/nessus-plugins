#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2005-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151741);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id(
    "CVE-2021-28163",
    "CVE-2021-28164",
    "CVE-2021-28165",
    "CVE-2021-28169"
  );

  script_name(english:"openSUSE 15 Security Update : jetty-minimal (openSUSE-SU-2021:2005-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2005-1 advisory.

  - In Eclipse Jetty 9.4.32 to 9.4.38, 10.0.0.beta2 to 10.0.1, and 11.0.0.beta2 to 11.0.1, if a user uses a
    webapps directory that is a symlink, the contents of the webapps directory is deployed as a static webapp,
    inadvertently serving the webapps themselves and anything else that might be in that directory.
    (CVE-2021-28163)

  - In Eclipse Jetty 9.4.37.v20210219 to 9.4.38.v20210224, the default compliance mode allows requests with
    URIs that contain %2e or %2e%2e segments to access protected resources within the WEB-INF directory. For
    example a request to /context/%2e/WEB-INF/web.xml can retrieve the web.xml file. This can reveal sensitive
    information regarding the implementation of a web application. (CVE-2021-28164)

  - In Eclipse Jetty 7.2.2 to 9.4.38, 10.0.0.alpha0 to 10.0.1, and 11.0.0.alpha0 to 11.0.1, CPU usage can
    reach 100% upon receiving a large invalid TLS frame. (CVE-2021-28165)

  - For Eclipse Jetty versions <= 9.4.40, <= 10.0.2, <= 11.0.2, it is possible for requests to the
    ConcatServlet with a doubly encoded path to access protected resources within the WEB-INF directory. For
    example a request to `/concat?/%2557EB-INF/web.xml` can retrieve the web.xml file. This can reveal
    sensitive information regarding the implementation of a web application. (CVE-2021-28169)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187117");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/U4KKN3NUA6VAZ6XTFLI3KB3IHAPVD46L/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7c84753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28163");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28164");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28165");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28169");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Jetty WEB-INF File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-continuation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-jaas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-javax-websocket-client-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-javax-websocket-server-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-jndi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-jsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-minimal-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-openid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-plus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-servlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-util-ajax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-servlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'jetty-annotations-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-client-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-continuation-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-http-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-io-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-jaas-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-javax-websocket-client-impl-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-javax-websocket-server-impl-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-jmx-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-jndi-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-jsp-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-minimal-javadoc-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-openid-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-plus-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-proxy-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-security-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-server-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-servlet-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-util-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-util-ajax-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-webapp-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-api-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-client-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-common-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-javadoc-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-server-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-websocket-servlet-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'jetty-xml-9.4.42-3.9.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jetty-annotations / jetty-client / jetty-continuation / jetty-http / etc');
}
