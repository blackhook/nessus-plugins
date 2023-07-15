#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-675.
#

include("compat.inc");

if (description)
{
  script_id(90268);
  script_version("2.5");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2016-1908");
  script_xref(name:"ALAS", value:"2016-675");

  script_name(english:"Amazon Linux AMI : openssh (ALAS-2016-675)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An access flaw was discovered in the OpenSSH client where it did not
correctly handle failures to generate authentication cookies for
untrusted X11 forwarding. A malicious or compromised remote X
application could possibly use this flaw to establish a trusted
connection to the local X server, even if only untrusted X11
forwarding was requested."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-675.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssh' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"openssh-6.6.1p1-25.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-clients-6.6.1p1-25.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-debuginfo-6.6.1p1-25.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-keycat-6.6.1p1-25.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-ldap-6.6.1p1-25.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-server-6.6.1p1-25.61.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"pam_ssh_agent_auth-0.9.3-9.25.61.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-clients / openssh-debuginfo / openssh-keycat / etc");
}
