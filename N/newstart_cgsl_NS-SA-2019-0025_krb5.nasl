#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0025. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127186);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-7562", "CVE-2017-11368");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : krb5 Multiple Vulnerabilities (NS-SA-2019-0025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has krb5 packages installed that are affected by
multiple vulnerabilities:

  - An authentication bypass flaw was found in the way
    krb5's certauth interface handled the validation of
    client certificates. A remote attacker able to
    communicate with the KDC could potentially use this flaw
    to impersonate arbitrary principals under rare and
    erroneous circumstances. (CVE-2017-7562)

  - A denial of service flaw was found in MIT Kerberos
    krb5kdc service. An authenticated attacker could use
    this flaw to cause krb5kdc to exit with an assertion
    failure by making an invalid S4U2Self or S4U2Proxy
    request. (CVE-2017-11368)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0025");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL krb5 packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "krb5-debuginfo-1.15.1-19.el7",
    "krb5-devel-1.15.1-19.el7",
    "krb5-libs-1.15.1-19.el7",
    "krb5-pkinit-1.15.1-19.el7",
    "krb5-server-1.15.1-19.el7",
    "krb5-server-ldap-1.15.1-19.el7",
    "krb5-workstation-1.15.1-19.el7",
    "libkadm5-1.15.1-19.el7"
  ],
  "CGSL MAIN 5.04": [
    "krb5-debuginfo-1.15.1-19.el7",
    "krb5-devel-1.15.1-19.el7",
    "krb5-libs-1.15.1-19.el7",
    "krb5-pkinit-1.15.1-19.el7",
    "krb5-server-1.15.1-19.el7",
    "krb5-server-ldap-1.15.1-19.el7",
    "krb5-workstation-1.15.1-19.el7",
    "libkadm5-1.15.1-19.el7"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5");
}
