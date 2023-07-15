#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0144. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127411);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2014-10072",
    "CVE-2017-18206",
    "CVE-2018-1083",
    "CVE-2018-1100"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : zsh Multiple Vulnerabilities (NS-SA-2019-0144)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has zsh packages installed that are affected by multiple
vulnerabilities:

  - A buffer overflow flaw was found in the zsh shell check
    path functionality. A local, unprivileged user can
    create a specially crafted message file, which, if used
    to set a custom you have new mail message, leads to
    code execution in the context of the user who receives
    the message. If the user affected is privileged, this
    leads to privilege escalation. (CVE-2018-1100)

  - A buffer overflow flaw was found in the zsh shell auto-
    complete functionality. A local, unprivileged user can
    create a specially crafted directory path which leads to
    code execution in the context of the user who tries to
    use auto-complete to traverse the before mentioned path.
    If the user affected is privileged, this leads to
    privilege escalation. (CVE-2018-1083)

  - A buffer overflow flaw was found in the zsh shell
    symbolic link resolver. A local, unprivileged user can
    create a specially crafted directory path which leads to
    a buffer overflow in the context of the user trying to
    do a symbolic link resolution in the aforementioned
    path. If the user affected is privileged, this leads to
    privilege escalation. (CVE-2017-18206)

  - A buffer overflow flaw was found in the zsh shell
    symbolic link resolver. A local, unprivileged user can
    create a specially crafted directory path which leads to
    a buffer overflow in the context of the user trying to
    do symbolic link resolution in the aforementioned path.
    An attacker could exploit this vulnerability to cause a
    denial of service condition on the target.
    (CVE-2014-10072)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0144");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL zsh packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18206");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/27");
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

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "zsh-4.3.11-9.el6_10",
    "zsh-debuginfo-4.3.11-9.el6_10",
    "zsh-html-4.3.11-9.el6_10"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zsh");
}
