##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163201);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/15");

  script_cve_id("CVE-2021-3981");

  script_name(english:"EulerOS Virtualization 2.10.0 : grub2 (EulerOS-SA-2022-2074)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the grub2 packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - A flaw in grub2 was found where its configuration file, known as grub.cfg, is being created with the wrong
    permission set allowing non privileged users to read its content. This represents a low severity
    confidentiality issue, as those users can eventually read any encrypted passwords present in grub.cfg.
    This flaw affects grub2 2.06 and previous versions. This issue has been fixed in grub upstream but no
    version with the fix is currently released. (CVE-2021-3981)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2074
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4414252a");
  script_set_attribute(attribute:"solution", value:
"Update the affected grub2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3981");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.10.0");
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
if (uvp != "2.10.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.10.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "grub2-common-2.04-16.h28.eulerosv2r10",
  "grub2-efi-x64-2.04-16.h28.eulerosv2r10",
  "grub2-efi-x64-modules-2.04-16.h28.eulerosv2r10",
  "grub2-pc-2.04-16.h28.eulerosv2r10",
  "grub2-pc-modules-2.04-16.h28.eulerosv2r10",
  "grub2-tools-2.04-16.h28.eulerosv2r10",
  "grub2-tools-efi-2.04-16.h28.eulerosv2r10",
  "grub2-tools-extra-2.04-16.h28.eulerosv2r10",
  "grub2-tools-minimal-2.04-16.h28.eulerosv2r10"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2");
}
