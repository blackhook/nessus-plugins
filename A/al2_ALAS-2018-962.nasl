#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-962.
#

include("compat.inc");

if (description)
{
  script_id(109130);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"ALAS", value:"2018-962");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Amazon Linux 2 : linux-firmware (ALAS-2018-962) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Speculative execution branch target injection

An industry-wide issue was found in the way many modern microprocessor
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
conducting targeted cache side-channel attacks.(CVE-2017-5715)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-962.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update linux-firmware' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:iwl7265-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:linux-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"iwl100-firmware-39.31.5.1-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl1000-firmware-39.31.5.1-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl105-firmware-18.168.6.1-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl135-firmware-18.168.6.1-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl2000-firmware-18.168.6.1-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl2030-firmware-18.168.6.1-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl3160-firmware-22.0.7.0-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl3945-firmware-15.32.2.9-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl4965-firmware-228.61.2.24-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl5000-firmware-8.83.5.1_1-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl5150-firmware-8.24.2.2-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl6000-firmware-9.221.4.1-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl6000g2a-firmware-17.168.5.3-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl6000g2b-firmware-17.168.5.2-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl6050-firmware-41.28.5.1-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl7260-firmware-22.0.7.0-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"iwl7265-firmware-22.0.7.0-58.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"linux-firmware-20170606-58.gitc990aae.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "iwl100-firmware / iwl1000-firmware / iwl105-firmware / etc");
}
