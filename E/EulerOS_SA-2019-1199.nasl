#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123885);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-15473"
  );

  script_name(english:"EulerOS Virtualization 2.5.4 : openssh (EulerOS-SA-2019-1199)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the openssh packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerability :

  - OpenSSH through 7.7 is prone to a user enumeration
    vulnerability due to not delaying bailout for an
    invalid authenticating user until after the packet
    containing the request has been fully parsed, related
    to auth2-gss.c, auth2-hostbased.c, and
    auth2-pubkey.c.(CVE-2018-15473)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1199
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb29c41f");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssh package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.5.4") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.4");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssh-7.4p1-16.h4",
        "openssh-clients-7.4p1-16.h4",
        "openssh-keycat-7.4p1-16.h4",
        "openssh-server-7.4p1-16.h4",
        "pam_ssh_agent_auth-0.10.3-2.16"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh");
}
