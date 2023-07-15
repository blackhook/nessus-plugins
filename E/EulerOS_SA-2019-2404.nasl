#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131896);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-3218",
    "CVE-2015-3255",
    "CVE-2015-4625",
    "CVE-2018-1116"
  );
  script_bugtraq_id(
    75267
  );

  script_name(english:"EulerOS 2.0 SP2 : polkit (EulerOS-SA-2019-2404)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the polkit packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in polkit before version 0.116. The
    implementation of the
    polkit_backend_interactive_authority_check_authorizatio
    n function in polkitd allows to test for authentication
    and trigger authentication of unrelated processes owned
    by other users. This may result in a local DoS and
    information disclosure.(CVE-2018-1116)

  - Integer overflow in the authentication_agent_new_cookie
    function in PolicyKit (aka polkit) before 0.113 allows
    local users to gain privileges by creating a large
    number of connections, which triggers the issuance of a
    duplicate cookie value.(CVE-2015-4625)

  - The authentication_agent_new function in
    polkitbackend/polkitbackendinteractiveauthority.c in
    PolicyKit (aka polkit) before 0.113 allows local users
    to cause a denial of service (NULL pointer dereference
    and polkitd daemon crash) by calling
    RegisterAuthenticationAgent with an invalid object
    path.(CVE-2015-3218)

  - The polkit_backend_action_pool_init function in
    polkitbackend/polkitbackendactionpool.c in PolicyKit
    (aka polkit) before 0.113 might allow local users to
    gain privileges via duplicate action IDs in action
    descriptions.(CVE-2015-3255)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2404
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e61b48c3");
  script_set_attribute(attribute:"solution", value:
"Update the affected polkit packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:polkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:polkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:polkit-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["polkit-0.112-7.h7",
        "polkit-devel-0.112-7.h7",
        "polkit-docs-0.112-7.h7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "polkit");
}
