#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1425.
#

include('compat.inc');

if (description)
{
  script_id(136530);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2020-10711");
  script_xref(name:"ALAS", value:"2020-1425");

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2020-1425)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A NULL pointer dereference flaw was found in the Linux kernel's
SELinux subsystem. This flaw occurs while importing the Commercial IP
Security Option (CIPSO) protocol's category bitmap into the SELinux
extensible bitmap via the' ebitmap_netlbl_import' routine. While
processing the CIPSO restricted bitmap tag in the
'cipso_v4_parsetag_rbm' routine, it sets the security attribute to
indicate that the category bitmap is present, even if it has not been
allocated. This issue leads to a NULL pointer dereference issue while
importing the same category bitmap into SELinux. This flaw allows a
remote network user to crash the system kernel, resulting in a denial
of service. (CVE-2020-10711)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1425.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10711");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-4.14.177-139.254");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("hotfixes.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  cve_list = make_list("CVE-2020-10711");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2020-1425");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}


flag = 0;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-4.14.177-139.254.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-debuginfo-4.14.177-139.254.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.14.177-139.254.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-devel-4.14.177-139.254.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"kernel-headers-4.14.177-139.254.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-livepatch-4.14.177-139.254-1.0-0.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-4.14.177-139.254.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-debuginfo-4.14.177-139.254.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"kernel-tools-devel-4.14.177-139.254.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"perf-4.14.177-139.254.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"perf-debuginfo-4.14.177-139.254.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"python-perf-4.14.177-139.254.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"python-perf-debuginfo-4.14.177-139.254.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-x86_64 / etc");
}
