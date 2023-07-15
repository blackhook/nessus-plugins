#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1348.
#

include("compat.inc");

if (description)
{
  script_id(130601);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/17");

  script_cve_id("CVE-2019-10153");
  script_xref(name:"ALAS", value:"2019-1348");

  script_name(english:"Amazon Linux 2 : fence-agents (ALAS-2019-1348)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was discovered in fence-agents, prior to version 4.3.4, where
using non-ASCII characters in a guest VM's comment or other fields
would cause fence_rhevm to exit with an exception. In cluster
environments, this could lead to preventing automated recovery or
otherwise denying service to clusters of which that VM is a
member.(CVE-2019-10153)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1348.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update fence-agents' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fence-agents-wti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/07");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"fence-agents-aliyun-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-all-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-amt-ws-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-apc-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-apc-snmp-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"fence-agents-aws-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-bladecenter-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-brocade-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-cisco-mds-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-cisco-ucs-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-common-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-compute-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-debuginfo-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-drac5-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-eaton-snmp-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-emerson-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-eps-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"fence-agents-gce-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-heuristics-ping-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-hpblade-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-ibmblade-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-ifmib-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-ilo-moonshot-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-ilo-mp-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-ilo-ssh-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-ilo2-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-intelmodular-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-ipdu-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-ipmilan-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-kdump-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-mpath-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-redfish-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-rhevm-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-rsa-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-rsb-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-sbd-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-scsi-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-virsh-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-vmware-rest-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-vmware-soap-4.2.1-24.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"fence-agents-wti-4.2.1-24.amzn2.0.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fence-agents-aliyun / fence-agents-all / fence-agents-amt-ws / etc");
}
