#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0031. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138773);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2019-6477", "CVE-2020-8616", "CVE-2020-8617");

  script_name(english:"NewStart CGSL MAIN 6.01 : bind Multiple Vulnerabilities (NS-SA-2020-0031)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.01, has bind packages installed that are affected by multiple
vulnerabilities:

  - With pipelining enabled each incoming query on a TCP
    connection requires a similar resource allocation to a
    query received via UDP or via TCP without pipelining
    enabled. A client using a TCP-pipelined connection to a
    server could consume more resources than the server has
    been provisioned to handle. When a TCP connection with a
    large number of pipelined queries is closed, the load on
    the server releasing these multiple resources can cause
    it to become unresponsive, even for queries that can be
    answered authoritatively or from cache. (This is most
    likely to be perceived as an intermittent server
    problem). (CVE-2019-6477)

  - A malicious actor who intentionally exploits this lack
    of effective limitation on the number of fetches
    performed when processing referrals can, through the use
    of specially crafted referrals, cause a recursing server
    to issue a very large number of fetches in an attempt to
    process the referral. This has at least two potential
    effects: The performance of the recursing server can
    potentially be degraded by the additional work required
    to perform these fetches, and The attacker can exploit
    this behavior to use the recursing server as a reflector
    in a reflection attack with a high amplification factor.
    (CVE-2020-8616)

  - Using a specially-crafted message, an attacker may
    potentially cause a BIND server to reach an inconsistent
    state if the attacker knows (or successfully guesses)
    the name of a TSIG key used by the server. Since BIND,
    by default, configures a local session key even on
    servers whose configuration does not otherwise make use
    of it, almost all current BIND servers are vulnerable.
    In releases of BIND dating from March 2018 and after, an
    assertion check in tsig.c detects this inconsistent
    state and deliberately exits. Prior to the introduction
    of the check the server would continue operating in an
    inconsistent state, with potentially harmful results.
    (CVE-2020-8617)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0031");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL bind packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8617");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8616");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 6.01")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.01');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 6.01": [
    "bind-9.11.13-5.el8_2",
    "bind-chroot-9.11.13-5.el8_2",
    "bind-debuginfo-9.11.13-5.el8_2",
    "bind-debugsource-9.11.13-5.el8_2",
    "bind-devel-9.11.13-5.el8_2",
    "bind-export-devel-9.11.13-5.el8_2",
    "bind-export-libs-9.11.13-5.el8_2",
    "bind-export-libs-debuginfo-9.11.13-5.el8_2",
    "bind-libs-9.11.13-5.el8_2",
    "bind-libs-debuginfo-9.11.13-5.el8_2",
    "bind-libs-lite-9.11.13-5.el8_2",
    "bind-libs-lite-debuginfo-9.11.13-5.el8_2",
    "bind-license-9.11.13-5.el8_2",
    "bind-lite-devel-9.11.13-5.el8_2",
    "bind-pkcs11-9.11.13-5.el8_2",
    "bind-pkcs11-debuginfo-9.11.13-5.el8_2",
    "bind-pkcs11-devel-9.11.13-5.el8_2",
    "bind-pkcs11-libs-9.11.13-5.el8_2",
    "bind-pkcs11-libs-debuginfo-9.11.13-5.el8_2",
    "bind-pkcs11-utils-9.11.13-5.el8_2",
    "bind-pkcs11-utils-debuginfo-9.11.13-5.el8_2",
    "bind-sdb-9.11.13-5.el8_2",
    "bind-sdb-chroot-9.11.13-5.el8_2",
    "bind-sdb-debuginfo-9.11.13-5.el8_2",
    "bind-utils-9.11.13-5.el8_2",
    "bind-utils-debuginfo-9.11.13-5.el8_2",
    "python3-bind-9.11.13-5.el8_2"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}

