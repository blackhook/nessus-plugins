#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131476);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-11763",
    "CVE-2018-17189",
    "CVE-2019-0211",
    "CVE-2019-0215",
    "CVE-2019-0220"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.3.0 : httpd (EulerOS-SA-2019-2311)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the httpd packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - In Apache HTTP Server 2.4.17 to 2.4.34, by sending
    continuous, large SETTINGS frames a client can occupy a
    connection, server thread and CPU time without any
    connection timeout coming to effect. This affects only
    HTTP/2 connections. A possible mitigation is to not
    enable the h2 protocol.(CVE-2018-11763)

  - In Apache HTTP Server 2.4 releases 2.4.17 to 2.4.38,
    with MPM event, worker or prefork, code executing in
    less-privileged child processes or threads (including
    scripts executed by an in-process scripting
    interpreter) could execute arbitrary code with the
    privileges of the parent process (usually root) by
    manipulating the scoreboard. Non-Unix systems are not
    affected.(CVE-2019-0211)

  - In Apache HTTP server versions 2.4.37 and prior, by
    sending request bodies in a slow loris way to plain
    resources, the h2 stream for that request unnecessarily
    occupied a server thread cleaning up that incoming
    data. This affects only HTTP/2 (mod_http2)
    connections.(CVE-2018-17189)

  - In Apache HTTP Server 2.4 releases 2.4.37 and 2.4.38, a
    bug in mod_ssl when using per-location client
    certificate verification with TLSv1.3 allowed a client
    to bypass configured access control
    restrictions.(CVE-2019-0215)

  - A vulnerability was found in Apache HTTP Server 2.4.0
    to 2.4.38. When the path component of a request URL
    contains multiple consecutive slashes ('/'), directives
    such as LocationMatch and RewriteRule must account for
    duplicates in regular expressions while other aspects
    of the servers processing will implicitly collapse
    them.(CVE-2019-0220)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2311
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74ae979f");
  script_set_attribute(attribute:"solution", value:
"Update the affected httpd packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0211");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.3.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.3.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.3.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["httpd-2.4.34-8.h8.eulerosv2r8",
        "httpd-filesystem-2.4.34-8.h8.eulerosv2r8",
        "httpd-tools-2.4.34-8.h8.eulerosv2r8",
        "mod_ssl-2.4.34-8.h8.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
