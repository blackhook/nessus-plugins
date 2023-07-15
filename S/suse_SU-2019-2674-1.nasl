#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2674-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(129966);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/19");

  script_cve_id("CVE-2017-16808", "CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14461", "CVE-2018-14462", "CVE-2018-14463", "CVE-2018-14464", "CVE-2018-14465", "CVE-2018-14466", "CVE-2018-14467", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14470", "CVE-2018-14879", "CVE-2018-14880", "CVE-2018-14881", "CVE-2018-14882", "CVE-2018-16227", "CVE-2018-16228", "CVE-2018-16229", "CVE-2018-16230", "CVE-2018-16300", "CVE-2018-16301", "CVE-2018-16451", "CVE-2018-16452", "CVE-2019-1010220", "CVE-2019-15166", "CVE-2019-15167");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : tcpdump (SUSE-SU-2019:2674-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tcpdump fixes the following issues :

CVE-2017-16808: Fixed a heap-based buffer over-read related to
aoe_print and lookup_emem (bsc#1068716 bsc#1153098).

CVE-2018-10103: Fixed a mishandling of the printing of SMB data
(bsc#1153098).

CVE-2018-10105: Fixed a mishandling of the printing of SMB data
(bsc#1153098).

CVE-2018-14461: Fixed a buffer over-read in print-ldp.c:ldp_tlv_print
(bsc#1153098).

CVE-2018-14462: Fixed a buffer over-read in print-icmp.c:icmp_print
(bsc#1153098).

CVE-2018-14463: Fixed a buffer over-read in print-vrrp.c:vrrp_print
(bsc#1153098).

CVE-2018-14464: Fixed a buffer over-read in
print-lmp.c:lmp_print_data_link_subobjs (bsc#1153098).

CVE-2018-14465: Fixed a buffer over-read in
print-rsvp.c:rsvp_obj_print (bsc#1153098).

CVE-2018-14466: Fixed a buffer over-read in print-rx.c:rx_cache_find
(bsc#1153098).

CVE-2018-14467: Fixed a buffer over-read in
print-bgp.c:bgp_capabilities_print (bsc#1153098).

CVE-2018-14468: Fixed a buffer over-read in print-fr.c:mfr_print
(bsc#1153098).

CVE-2018-14469: Fixed a buffer over-read in
print-isakmp.c:ikev1_n_print (bsc#1153098).

CVE-2018-14470: Fixed a buffer over-read in
print-babel.c:babel_print_v2 (bsc#1153098).

CVE-2018-14879: Fixed a buffer overflow in the command-line argument
parser (bsc#1153098).

CVE-2018-14880: Fixed a buffer over-read in the OSPFv3 parser
(bsc#1153098).

CVE-2018-14881: Fixed a buffer over-read in the BGP parser
(bsc#1153098).

CVE-2018-14882: Fixed a buffer over-read in the ICMPv6 parser
(bsc#1153098).

CVE-2018-16227: Fixed a buffer over-read in the IEEE 802.11 parser in
print-802_11.c for the Mesh Flags subfield (bsc#1153098).

CVE-2018-16228: Fixed a buffer over-read in the HNCP parser
(bsc#1153098).

CVE-2018-16229: Fixed a buffer over-read in the DCCP parser
(bsc#1153098).

CVE-2018-16230: Fixed a buffer over-read in the BGP parser in
print-bgp.c:bgp_attr_print (bsc#1153098).

CVE-2018-16300: Fixed an unlimited recursion in the BGP parser that
allowed denial-of-service by stack consumption (bsc#1153098).

CVE-2018-16301: Fixed a buffer overflow (bsc#1153332 bsc#1153098).

CVE-2018-16451: Fixed several buffer over-reads in
print-smb.c:print_trans() for \MAILSLOT\BROWSE and \PIPE\LANMAN
(bsc#1153098).

CVE-2018-16452: Fixed a stack exhaustion in smbutil.c:smb_fdata
(bsc#1153098).

CVE-2019-15166: Fixed a bounds check in lmp_print_data_link_subobjs
(bsc#1153098).

CVE-2019-15167: Fixed a vulnerability in VRRP (bsc#1153098).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16808/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10103/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10105/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14461/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14462/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14463/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14464/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14465/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14466/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14467/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14468/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14469/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14470/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14879/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14880/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14881/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14882/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16227/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16228/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16229/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16230/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16300/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16301/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16451/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16452/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-1010220/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15166/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-15167/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192674-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7524703"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2674=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-2674=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"tcpdump-4.9.2-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"tcpdump-debuginfo-4.9.2-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"tcpdump-debugsource-4.9.2-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tcpdump-4.9.2-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tcpdump-debuginfo-4.9.2-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tcpdump-debugsource-4.9.2-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"tcpdump-4.9.2-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"tcpdump-debuginfo-4.9.2-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"tcpdump-debugsource-4.9.2-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tcpdump-4.9.2-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tcpdump-debuginfo-4.9.2-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tcpdump-debugsource-4.9.2-3.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpdump");
}
