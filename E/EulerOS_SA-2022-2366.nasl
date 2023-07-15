#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165362);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/23");

  script_cve_id("CVE-2020-24612");

  script_name(english:"EulerOS Virtualization 2.9.1 : selinux-policy (EulerOS-SA-2022-2366)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the selinux-policy packages installed, the EulerOS Virtualization installation on the
remote host is affected by the following vulnerabilities :

  - An issue was discovered in the selinux-policy (aka Reference Policy) package 3.14 through 2020-08-24
    because the .config/Yubico directory is mishandled. Consequently, when SELinux is in enforced mode,
    pam-u2f is not allowed to read the user's U2F configuration file. If configured with the nouserok option
    (the default when configured by the authselect tool), and that file cannot be read, the second factor is
    disabled. An attacker with only the knowledge of the password can then log in, bypassing 2FA.
    (CVE-2020-24612)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2366
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab9f5337");
  script_set_attribute(attribute:"solution", value:
"Update the affected selinux-policy packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:selinux-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:selinux-policy-minimum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:selinux-policy-mls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:selinux-policy-sandbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:selinux-policy-targeted");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

var flag = 0;

var pkgs = [
  "selinux-policy-3.14.2-52.h29.eulerosv2r9",
  "selinux-policy-minimum-3.14.2-52.h29.eulerosv2r9",
  "selinux-policy-mls-3.14.2-52.h29.eulerosv2r9",
  "selinux-policy-sandbox-3.14.2-52.h29.eulerosv2r9",
  "selinux-policy-targeted-3.14.2-52.h29.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "selinux-policy");
}
