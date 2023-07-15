#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1075.
#

include("compat.inc");

if (description)
{
  script_id(117347);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2018-15473");
  script_xref(name:"ALAS", value:"2018-1075");

  script_name(english:"Amazon Linux AMI : openssh (ALAS-2018-1075)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSSH is prone to a user enumeration vulnerability due to not
delaying bailout for an invalid authenticating user until after the
packet containing the request has been fully parsed, related to
auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.(CVE-2018-15473)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1075.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssh' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"openssh-7.4p1-16.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-cavs-7.4p1-16.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-clients-7.4p1-16.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-debuginfo-7.4p1-16.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-keycat-7.4p1-16.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-ldap-7.4p1-16.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-server-7.4p1-16.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"pam_ssh_agent_auth-0.10.3-2.16.71.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-cavs / openssh-clients / openssh-debuginfo / etc");
}
