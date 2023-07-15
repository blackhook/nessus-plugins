#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2539-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(177440);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id("CVE-2023-26048", "CVE-2023-26049");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2539-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : jetty-minimal (SUSE-SU-2023:2539-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:2539-1 advisory.

  - Jetty is a java based web server and servlet engine. In affected versions servlets with multipart support
    (e.g. annotated with `@MultipartConfig`) that call `HttpServletRequest.getParameter()` or
    `HttpServletRequest.getParts()` may cause `OutOfMemoryError` when the client sends a multipart request
    with a part that has a name but no filename and very large content. This happens even with the default
    settings of `fileSizeThreshold=0` which should stream the whole part content to disk. An attacker client
    may send a large multipart request and cause the server to throw `OutOfMemoryError`. However, the server
    may be able to recover after the `OutOfMemoryError` and continue its service -- although it may take some
    time. This issue has been patched in versions 9.4.51, 10.0.14, and 11.0.14. Users are advised to upgrade.
    Users unable to upgrade may set the multipart parameter `maxRequestSize` which must be set to a non-
    negative value, so the whole multipart content is limited (although still read into memory).
    (CVE-2023-26048)

  - Jetty is a java based web server and servlet engine. Nonstandard cookie parsing in Jetty may allow an
    attacker to smuggle cookies within other cookies, or otherwise perform unintended behavior by tampering
    with the cookie parsing mechanism. If Jetty sees a cookie VALUE that starts with `` (double quote), it
    will continue to read the cookie string until it sees a closing quote -- even if a semicolon is
    encountered. So, a cookie header such as: `DISPLAY_LANGUAGE=b; JSESSIONID=1337; c=d` will be parsed as
    one cookie, with the name DISPLAY_LANGUAGE and a value of b; JSESSIONID=1337; c=d instead of 3 separate
    cookies. This has security implications because if, say, JSESSIONID is an HttpOnly cookie, and the
    DISPLAY_LANGUAGE cookie value is rendered on the page, an attacker can smuggle the JSESSIONID cookie into
    the DISPLAY_LANGUAGE cookie and thereby exfiltrate it. This is significant when an intermediary is
    enacting some policy based on cookies, so a smuggled cookie can bypass that policy yet still be seen by
    the Jetty server or its logging system. This issue has been addressed in versions 9.4.51, 10.0.14,
    11.0.14, and 12.0.0.beta0 and users are advised to upgrade. There are no known workarounds for this issue.
    (CVE-2023-26049)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210621");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-June/029919.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-26048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-26049");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jetty-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jetty-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jetty-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jetty-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jetty-servlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jetty-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:jetty-util-ajax");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.4|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'jetty-http-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-http-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-io-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-io-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-security-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-security-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-server-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-server-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-servlet-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-servlet-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-util-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-util-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-util-ajax-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-util-ajax-9.4.51-150200.3.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'jetty-http-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-http-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-io-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-io-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-security-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-security-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-server-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-server-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-servlet-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-servlet-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-util-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-util-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-util-ajax-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-util-ajax-9.4.51-150200.3.19.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'jetty-http-9.4.51-150200.3.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'jetty-io-9.4.51-150200.3.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'jetty-security-9.4.51-150200.3.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'jetty-server-9.4.51-150200.3.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'jetty-servlet-9.4.51-150200.3.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'jetty-util-9.4.51-150200.3.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'jetty-util-ajax-9.4.51-150200.3.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'jetty-annotations-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-ant-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-cdi-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-client-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-continuation-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-deploy-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-fcgi-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-http-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-http-spi-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-io-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-jaas-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-jmx-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-jndi-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-jsp-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-minimal-javadoc-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-openid-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-plus-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-proxy-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-quickstart-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-rewrite-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-security-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-server-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-servlet-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-servlets-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-start-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-util-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-util-ajax-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-webapp-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-xml-9.4.51-150200.3.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'jetty-annotations-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-ant-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-cdi-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-client-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-continuation-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-deploy-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-fcgi-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-http-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-http-spi-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-io-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-jaas-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-jmx-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-jndi-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-jsp-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-minimal-javadoc-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-openid-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-plus-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-proxy-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-quickstart-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-rewrite-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-security-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-server-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-servlet-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-servlets-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-start-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-util-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-util-ajax-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-webapp-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'jetty-xml-9.4.51-150200.3.19.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jetty-annotations / jetty-ant / jetty-cdi / jetty-client / etc');
}
