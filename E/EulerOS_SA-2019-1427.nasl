#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124930);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id(
    "CVE-2010-0743",
    "CVE-2010-2221"
  );
  script_bugtraq_id(
    39127,
    41327
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : scsi-target-utils (EulerOS-SA-2019-1427)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the scsi-target-utils package installed,
the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - Multiple buffer overflows in the iSNS implementation in
    isns.c in (1) Linux SCSI target framework (aka tgt or
    scsi-target-utils) before 1.0.6, (2) iSCSI Enterprise
    Target (aka iscsitarget or IET) 1.4.20.1 and earlier,
    and (3) Generic SCSI Target Subsystem for Linux (aka
    SCST or iscsi-scst) 1.0.1.1 and earlier allow remote
    attackers to cause a denial of service (memory
    corruption and daemon crash) or possibly execute
    arbitrary code via (a) a long iSCSI Name string in an
    SCN message or (b) an invalid PDU.(CVE-2010-2221)

  - Multiple format string vulnerabilities in isns.c in (1)
    Linux SCSI target framework (aka tgt or
    scsi-target-utils) 1.0.3, 0.9.5, and earlier and (2)
    iSCSI Enterprise Target (aka iscsitarget) 0.4.16 allow
    remote attackers to cause a denial of service (tgtd
    daemon crash) or possibly have unspecified other impact
    via vectors that involve the isns_attr_query and
    qry_rsp_handle functions, and are related to (a) client
    appearance and (b) client disappearance
    messages.(CVE-2010-0743)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1427
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ef28187");
  script_set_attribute(attribute:"solution", value:
"Update the affected scsi-target-utils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:scsi-target-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["scsi-target-utils-1.0.70-4.h3"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "scsi-target-utils");
}
