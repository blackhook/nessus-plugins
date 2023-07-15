#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0121.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101200);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-7645", "CVE-2017-7895", "CVE-2017-8890");

  script_name(english:"OracleVM 3.2 : Unbreakable / etc (OVMSA-2017-0121)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - nfsd: check for oversized NFSv2/v3 arguments (J. Bruce
    Fields) [Orabug: 26366024] (CVE-2017-7645)

  - dm mpath: allow ioctls to trigger pg init (Mikulas
    Patocka) [Orabug: 25645229]

  - xen/manage: Always freeze/thaw processes when
    suspend/resuming (Ross Lagerwall) [Orabug: 25795530]

  - lpfc cannot establish connection with targets that send
    PRLI under P2P mode (Joe Jin) [Orabug: 25955028]

  - nvme: Handle PM1725 HIL reset (Martin K. Petersen)
    [Orabug: 26277602]

  - dccp/tcp: do not inherit mc_list from parent (Eric
    Dumazet) [Orabug: 26108573] (CVE-2017-8890)

  - cifs: adjust sequence number downward after signing
    NT_CANCEL request (Albert Barbe)

  - nfsd: stricter decoding of write-like NFSv2/v3 ops (J.
    Bruce Fields) [Orabug: 25986995] (CVE-2017-7895)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2017-July/000749.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-2.6.39-400.297.3.el5uek")) flag++;
if (rpm_check(release:"OVS3.2", reference:"kernel-uek-firmware-2.6.39-400.297.3.el5uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
