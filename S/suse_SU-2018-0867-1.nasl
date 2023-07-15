#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0867-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108831);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-17997", "CVE-2018-7320", "CVE-2018-7321", "CVE-2018-7322", "CVE-2018-7323", "CVE-2018-7324", "CVE-2018-7325", "CVE-2018-7326", "CVE-2018-7327", "CVE-2018-7328", "CVE-2018-7329", "CVE-2018-7330", "CVE-2018-7331", "CVE-2018-7332", "CVE-2018-7333", "CVE-2018-7334", "CVE-2018-7335", "CVE-2018-7336", "CVE-2018-7337", "CVE-2018-7417", "CVE-2018-7418", "CVE-2018-7419", "CVE-2018-7420", "CVE-2018-7421");

  script_name(english:"SUSE SLES11 Security Update : wireshark (SUSE-SU-2018:0867-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for wireshark fixes the following issues: Security issue
fixed (bsc#1082692) :

  - CVE-2018-7335: The IEEE 802.11 dissector could crash
    (wnpa-sec-2018-05)

  - CVE-2018-7321: thrift long dissector loop
    (dissect_thrift_map)

  - CVE-2018-7322: DICOM: inifinite loop (dissect_dcm_tag)

  - CVE-2018-7323: WCCP: very long loop
    (dissect_wccp2_alternate_mask_value_set_element)

  - CVE-2018-7324: SCCP: infinite loop
    (dissect_sccp_optional_parameters)

  - CVE-2018-7325: RPKI-Router Protocol: infinite loop
    (dissect_rpkirtr_pdu)

  - CVE-2018-7326: LLTD: infinite loop (dissect_lltd_tlv)

  - CVE-2018-7327: openflow_v6: infinite loop
    (dissect_openflow_bundle_control_v6)

  - CVE-2018-7328: USB-DARWIN: long loop
    (dissect_darwin_usb_iso_transfer)

  - CVE-2018-7329: S7COMM: infinite loop
    (s7comm_decode_ud_cpu_alarm_main)

  - CVE-2018-7330: thread_meshcop: infinite loop
    (get_chancount)

  - CVE-2018-7331: GTP: infinite loop
    (dissect_gprscdr_GGSNPDPRecord, dissect_ber_set)

  - CVE-2018-7332: RELOAD: infinite loop (dissect_statans)

  - CVE-2018-7333: RPCoRDMA: infinite loop in
    get_write_list_chunk_count

  - CVE-2018-7421: Multiple dissectors could go into large
    infinite loops (wnpa-sec-2018-06)

  - CVE-2018-7334: The UMTS MAC dissector could crash
    (wnpa-sec-2018-07)

  - CVE-2018-7337: The DOCSIS dissector could crash
    (wnpa-sec-2018-08)

  - CVE-2018-7336: The FCP dissector could crash
    (wnpa-sec-2018-09)

  - CVE-2018-7320: The SIGCOMP dissector could crash
    (wnpa-sec-2018-10)

  - CVE-2018-7420: The pcapng file parser could crash
    (wnpa-sec-2018-11)

  - CVE-2018-7417: The IPMI dissector could crash
    (wnpa-sec-2018-12)

  - CVE-2018-7418: The SIGCOMP dissector could crash
    (wnpa-sec-2018-13)

  - CVE-2018-7419: The NBAP disssector could crash
    (wnpa-sec-2018-14)

  - CVE-2017-17997: Misuse of NULL pointer in MRDISC
    dissector (bsc#1077080).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17997/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7320/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7321/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7322/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7323/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7324/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7325/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7326/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7327/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7328/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7329/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7330/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7331/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7332/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7333/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7334/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7335/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7336/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7337/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7417/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7418/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7419/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7420/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7421/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180867-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b54c52a3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-wireshark-13547=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-wireshark-13547=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-wireshark-13547=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwireshark8-2.2.13-40.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwiretap6-2.2.13-40.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwscodecs1-2.2.13-40.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwsutil7-2.2.13-40.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"wireshark-2.2.13-40.22.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"wireshark-gtk-2.2.13-40.22.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
