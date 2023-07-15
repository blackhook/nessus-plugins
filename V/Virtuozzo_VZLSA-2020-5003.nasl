#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144430);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id(
    "CVE-2020-11078"
  );

  script_name(english:"Virtuozzo 7 : fence-agents-aliyun / fence-agents-all / etc (VZLSA-2020-5003)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in the RHSA-2020:5003 advisory.

  - python-httplib2: CRLF injection via an attacker controlled unescaped part of uri for httplib2.Http.request     function (CVE-2020-11078)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2020-5003.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5a9c7ce");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:5003");
  script_set_attribute(attribute:"solution", value:
"Update the affected fence-agents-aliyun / fence-agents-all / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-azure-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-lpar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:fence-agents-wti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["fence-agents-aliyun-4.2.1-41.vl7.2",
        "fence-agents-all-4.2.1-41.vl7.2",
        "fence-agents-amt-ws-4.2.1-41.vl7.2",
        "fence-agents-apc-4.2.1-41.vl7.2",
        "fence-agents-apc-snmp-4.2.1-41.vl7.2",
        "fence-agents-aws-4.2.1-41.vl7.2",
        "fence-agents-azure-arm-4.2.1-41.vl7.2",
        "fence-agents-bladecenter-4.2.1-41.vl7.2",
        "fence-agents-brocade-4.2.1-41.vl7.2",
        "fence-agents-cisco-mds-4.2.1-41.vl7.2",
        "fence-agents-cisco-ucs-4.2.1-41.vl7.2",
        "fence-agents-common-4.2.1-41.vl7.2",
        "fence-agents-compute-4.2.1-41.vl7.2",
        "fence-agents-drac5-4.2.1-41.vl7.2",
        "fence-agents-eaton-snmp-4.2.1-41.vl7.2",
        "fence-agents-emerson-4.2.1-41.vl7.2",
        "fence-agents-eps-4.2.1-41.vl7.2",
        "fence-agents-gce-4.2.1-41.vl7.2",
        "fence-agents-heuristics-ping-4.2.1-41.vl7.2",
        "fence-agents-hpblade-4.2.1-41.vl7.2",
        "fence-agents-ibmblade-4.2.1-41.vl7.2",
        "fence-agents-ifmib-4.2.1-41.vl7.2",
        "fence-agents-ilo-moonshot-4.2.1-41.vl7.2",
        "fence-agents-ilo-mp-4.2.1-41.vl7.2",
        "fence-agents-ilo-ssh-4.2.1-41.vl7.2",
        "fence-agents-ilo2-4.2.1-41.vl7.2",
        "fence-agents-intelmodular-4.2.1-41.vl7.2",
        "fence-agents-ipdu-4.2.1-41.vl7.2",
        "fence-agents-ipmilan-4.2.1-41.vl7.2",
        "fence-agents-kdump-4.2.1-41.vl7.2",
        "fence-agents-lpar-4.2.1-41.vl7.2",
        "fence-agents-mpath-4.2.1-41.vl7.2",
        "fence-agents-redfish-4.2.1-41.vl7.2",
        "fence-agents-rhevm-4.2.1-41.vl7.2",
        "fence-agents-rsa-4.2.1-41.vl7.2",
        "fence-agents-rsb-4.2.1-41.vl7.2",
        "fence-agents-sbd-4.2.1-41.vl7.2",
        "fence-agents-scsi-4.2.1-41.vl7.2",
        "fence-agents-virsh-4.2.1-41.vl7.2",
        "fence-agents-vmware-rest-4.2.1-41.vl7.2",
        "fence-agents-vmware-soap-4.2.1-41.vl7.2",
        "fence-agents-wti-4.2.1-41.vl7.2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fence-agents-aliyun / fence-agents-all / etc");
}
