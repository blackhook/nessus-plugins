#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101472);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id("CVE-2017-7494");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Virtuozzo 6 : libsmbclient / libsmbclient-devel / samba / etc (VZLSA-2017-1270)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for samba is now available for Red Hat Enterprise Linux 6
and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) protocol and the related Common Internet File System (CIFS)
protocol, which allow PC-compatible machines to share files, printers,
and various information.

Security Fix(es) :

* A remote code execution flaw was found in Samba. A malicious
authenticated samba client, having write access to the samba share,
could use this flaw to execute arbitrary code as root. (CVE-2017-7494)

Red Hat would like to thank the Samba project for reporting this
issue. Upstream acknowledges steelo as the original reporter.

Note that Tenable Network Security has attempted to extract the
preceding description block directly from the corresponding Red Hat
security advisory. Virtuozzo provides no description for VZLSA
advisories. Tenable has attempted to automatically clean and format
it as much as possible without introducing additional issues.");
  # http://repo.virtuozzo.com/vzlinux/announcements/json/VZLSA-2017-1270.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec8c6e85");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017-1270");
  script_set_attribute(attribute:"solution", value:
"Update the affected libsmbclient / libsmbclient-devel / samba / etc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7494");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba is_known_pipename() Arbitrary Module Load');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:samba-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:samba-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 6.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["libsmbclient-3.6.23-43.vl6",
        "libsmbclient-devel-3.6.23-43.vl6",
        "samba-3.6.23-43.vl6",
        "samba-client-3.6.23-43.vl6",
        "samba-common-3.6.23-43.vl6",
        "samba-doc-3.6.23-43.vl6",
        "samba-domainjoin-gui-3.6.23-43.vl6",
        "samba-glusterfs-3.6.23-43.vl6",
        "samba-swat-3.6.23-43.vl6",
        "samba-winbind-3.6.23-43.vl6",
        "samba-winbind-clients-3.6.23-43.vl6",
        "samba-winbind-devel-3.6.23-43.vl6",
        "samba-winbind-krb5-locator-3.6.23-43.vl6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-6", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / etc");
}
