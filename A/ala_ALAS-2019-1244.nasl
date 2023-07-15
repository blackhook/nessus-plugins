#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1244.
#

include("compat.inc");

if (description)
{
  script_id(127072);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/06");

  script_cve_id("CVE-2018-5743");
  script_xref(name:"ALAS", value:"2019-1244");

  script_name(english:"Amazon Linux AMI : bind (ALAS-2019-1244)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way bind implemented tunable which limited
simultaneous TCP client connections. A remote attacker could use this
flaw to exhaust the pool of file descriptors available to named,
potentially affecting network connections and the management of files
such as log files or zone journal files. In cases where the named
process is not limited by OS-enforced per-process limits, this could
additionally potentially lead to exhaustion of all available free file
descriptors on that system. (CVE-2018-5743)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1244.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update bind' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"bind-9.8.2-0.68.rc1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-chroot-9.8.2-0.68.rc1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-debuginfo-9.8.2-0.68.rc1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-devel-9.8.2-0.68.rc1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-libs-9.8.2-0.68.rc1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-sdb-9.8.2-0.68.rc1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-utils-9.8.2-0.68.rc1.60.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-devel / bind-libs / etc");
}
