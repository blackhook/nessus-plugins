#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-996.
#

include("compat.inc");

if (description)
{
  script_id(109185);
  script_version("1.1");
  script_cvs_date("Date: 2018/04/20 11:38:50");

  script_xref(name:"ALAS", value:"2018-996");

  script_name(english:"Amazon Linux AMI : stunnel / amazon-efs-utils (ALAS-2018-996)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update adds the checkHost option to stunnel, which verifies the
host of the peer certificate subject. Certificates are accepted if no
checkHost option was specified, or the host name of the peer
certificate matches any of the hosts specified with checkHost.

This update adds the OCSPaia option to stunnel, which enables stunnel
to validate certificates with the list of OCSP responder URLs
retrieved from their AIA (Authority Information Access) extension.

This update adds the verify option to stunnel, which verifies the peer
certificate. The different verification levels are as follows :

level 0 - request and ignore the peer certificate

level 1 - verify the peer certificate if present

level 2 - verify the peer certificate

level 3 - verify the peer against a locally installed certificate

level 4 - ignore the chain and only verify the peer certificate

default - no verify

Certificates for verification needs to be stored either in the file
specified with CAfile, or in the directory specified with CApath.

This update enables amazon-efs-utils to use new features added to
stunnel to encrypt data in transit to EFS"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-996.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update stunnel' to update your system.

Run 'yum update amazon-efs-utils' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:amazon-efs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:stunnel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:stunnel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"amazon-efs-utils-1.2-1.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"stunnel-4.56-4.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"stunnel-debuginfo-4.56-4.13.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "amazon-efs-utils / stunnel / stunnel-debuginfo");
}
