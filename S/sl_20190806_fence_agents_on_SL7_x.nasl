#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(128217);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2019-10153");

  script_name(english:"Scientific Linux Security Update : fence-agents on SL7.x x86_64 (20190806)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"* fence-agents: mis-handling of non-ASCII characters in guest comment
fields (CVE-2019-10153)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=33390
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a22fa711"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-azure-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:fence-agents-wti");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-aliyun-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-all-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-amt-ws-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-apc-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-apc-snmp-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-aws-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-azure-arm-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-bladecenter-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-brocade-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-cisco-mds-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-cisco-ucs-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-common-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-compute-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-debuginfo-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-drac5-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-eaton-snmp-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-emerson-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-eps-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-gce-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-heuristics-ping-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-hpblade-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-ibmblade-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-ifmib-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-ilo-moonshot-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-ilo-mp-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-ilo-ssh-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-ilo2-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-intelmodular-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-ipdu-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-ipmilan-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-kdump-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-mpath-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-redfish-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-rhevm-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-rsa-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-rsb-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-sbd-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-scsi-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-virsh-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-vmware-rest-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-vmware-soap-4.2.1-24.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"fence-agents-wti-4.2.1-24.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fence-agents-aliyun / fence-agents-all / fence-agents-amt-ws / etc");
}
