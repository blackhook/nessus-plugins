#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1141.
#

include("compat.inc");

if (description)
{
  script_id(121050);
  script_version("1.4");
  script_cvs_date("Date: 2019/05/17  9:44:16");

  script_cve_id("CVE-2018-16864", "CVE-2018-16865", "CVE-2018-16866");
  script_xref(name:"ALAS", value:"2019-1141");

  script_name(english:"Amazon Linux 2 : systemd (ALAS-2019-1141)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Large syslogd messages sent to journald can cause stack corruption,
causing journald to crash. The version of systemd on Amazon Linux 2 is
not vulnerable to privilege escalation in this case. (CVE-2018-16864)

Large native messages to journald can cause stack corruption, leading
to possible local privilege escalation.(CVE-2018-16865)

Please note, if you have systemd-journald-remote configured over http,
then you could be open to remote escalation on previous versions of
the systemd package. The systemd-journald-remote service is not
installed by default on Amazon Linux 2, and when installed and
enabled, the default configuration is to use https. (CVE-2018-16865)

An out-of-bounds read in journald, triggered by a specially crafted
message, can be used to leak information through the journal file
(CVE-2018-16866)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1141.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update systemd' then reboot your instance, to update your
system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"libgudev1-219-57.amzn2.0.7")) flag++;
if (rpm_check(release:"AL2", reference:"libgudev1-devel-219-57.amzn2.0.7")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-219-57.amzn2.0.7")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-debuginfo-219-57.amzn2.0.7")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-devel-219-57.amzn2.0.7")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-journal-gateway-219-57.amzn2.0.7")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-libs-219-57.amzn2.0.7")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-networkd-219-57.amzn2.0.7")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-python-219-57.amzn2.0.7")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-resolved-219-57.amzn2.0.7")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-sysv-219-57.amzn2.0.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgudev1 / libgudev1-devel / systemd / systemd-debuginfo / etc");
}
