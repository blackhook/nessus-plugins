#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-5454.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33234);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2008-1673");
  script_bugtraq_id(29589);
  script_xref(name:"FEDORA", value:"2008-5454");

  script_name(english:"Fedora 8 : kernel-2.6.25.6-27.fc8 (2008-5454)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to kernel 2.6.25.6:
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.5
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.6
CVE-2008-1673: The asn1 implementation in (a) the Linux kernel 2.4
before 2.4.36.6 and 2.6 before 2.6.25.5, as used in the cifs and
ip_nat_snmp_basic modules; and (b) the gxsnmp package; does not
properly validate length values during decoding of ASN.1 BER data,
which allows remote attackers to cause a denial of service (crash) or
execute arbitrary code via (1) a length greater than the working
buffer, which can lead to an unspecified overflow; (2) an oid length
of zero, which can lead to an off-by-one error; or (3) an indefinite
length for a primitive encoding. Bugs fixed: 224005 - pata_pcmcia
fails 326411 - Freeze On Boot w/ Audigy PCMCIA 450332 - F8 - System
Lockup after kernel 2.6.25.4-10 450499 - kernel-2.6.25.4-10.fc8 breaks
setkey -m tunnel options in ipsec 450501

  - User Mode Linux (UML) broken on Fedora 9 (and now F8,
    too) Additional bugs fixed: F9#447518 - Call to capget()
    overflows buffers F9#450191 - DMA mode disabled for DVD
    drive, reverts to PIO4 F9#439197 - thinkpad x61t crash
    when undocking F9#447812 - Netlink messages from 'tc' to
    sch_netem module are not interpreted correctly F9#449817
    - SD card reader causes kernel panic during startup if
    card inserted Additional updates/fixes: - Fix oops in
    lirc_i2c module - Add lirc support for additional MCE
    receivers - Upstream wireless updates from 2008-05-22
    (http://marc.info/?l=linux-
    wireless&m=121146112404515&w=2) - Upstream wireless
    fixes from 2008-05-28
    (http://marc.info/?l=linux-wireless&m=121201250110162&w=
    2) - Upstream wireless fixes from 2008-06-03
    (http://marc.info/?l=linux-
    wireless&m=121252137324941&w=2) - Upstream wireless
    fixes from 2008-06-09
    (http://marc.info/?l=linux-kernel&m=121304710726632&w=2)
    - Upstream wireless updates from 2008-06-09
    (http://marc.info/?l=linux-
    netdev&m=121304710526613&w=2)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://marc.info/?l=linux-
  script_set_attribute(
    attribute:"see_also",
    value:"https://marc.info/?l=linux-"
  );
  # http://marc.info/?l=linux-kernel&m=121304710726632&w=2
  script_set_attribute(
    attribute:"see_also",
    value:"https://marc.info/?l=linux-kernel&m=121304710726632&w=2"
  );
  # http://marc.info/?l=linux-wireless&m=121201250110162&w=2
  script_set_attribute(
    attribute:"see_also",
    value:"https://marc.info/?l=linux-wireless&m=121201250110162&w=2"
  );
  # http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?497677c6"
  );
  # http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6881f29a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=443962"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-June/011486.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ecddb40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"kernel-2.6.25.6-27.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
