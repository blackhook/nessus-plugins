#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-942.
#

include("compat.inc");

if (description)
{
  script_id(106169);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"ALAS", value:"2018-942");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Amazon Linux AMI : qemu-kvm (ALAS-2018-942) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of instructions (a
commonly used performance optimization). There are three primary
variants of the issue which differ in the way the speculative
execution can be exploited. Variant CVE-2017-5715 triggers the
speculative execution by utilizing branch target injection. It relies
on the presence of a precisely-defined instruction sequence in the
privileged code as well as the fact that memory accesses may cause
allocation into the microprocessor's data cache even for speculatively
executed instructions that never actually commit (retire). As a
result, an unprivileged attacker could use this flaw to cross the
syscall and guest/host boundaries and read privileged memory by
conducting targeted cache side-channel attacks. (CVE-2017-5715)

This update provides fixes for CVE-2017-5715 for qemu-kvm. A kernel
update is still required on all hosts (both virtual and physical) to
fully address this CVE."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-942.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update qemu-kvm' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-img-1.5.3-141.6.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-1.5.3-141.6.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-141.6.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-debuginfo-1.5.3-141.6.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-141.6.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img / qemu-kvm / qemu-kvm-common / qemu-kvm-debuginfo / etc");
}
