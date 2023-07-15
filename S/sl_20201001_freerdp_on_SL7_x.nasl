#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(141720);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-11018", "CVE-2020-11019", "CVE-2020-11038", "CVE-2020-11039", "CVE-2020-11040", "CVE-2020-11041", "CVE-2020-11042", "CVE-2020-11043", "CVE-2020-11044", "CVE-2020-11045", "CVE-2020-11046", "CVE-2020-11047", "CVE-2020-11048", "CVE-2020-11049", "CVE-2020-11058", "CVE-2020-11085", "CVE-2020-11086", "CVE-2020-11087", "CVE-2020-11088", "CVE-2020-11089", "CVE-2020-11522", "CVE-2020-11525", "CVE-2020-11526", "CVE-2020-13396", "CVE-2020-13397");

  script_name(english:"Scientific Linux Security Update : freerdp on SL7.x x86_64 (20201001)");
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
"Security Fix(es) :

  - freerdp: Out of bound read in
    cliprdr_server_receive_capabilities (CVE-2020-11018)

  - freerdp: Out of bound read/write in usb redirection
    channel (CVE-2020-11039)

  - freerdp: out-of-bounds read in update_read_icon_info
    function (CVE-2020-11042)

  - freerdp: out-of-bounds read in
    autodetect_recv_bandwidth_measure_results function
    (CVE-2020-11047)

  - freerdp: Out-of-bounds read in
    ntlm_read_ChallengeMessage in
    winpr/libwinpr/sspi/NTLM/ntlm_message.c.
    (CVE-2020-13396)

  - freerdp: Out-of-bounds read in security_fips_decrypt in
    libfreerdp/core/security.c (CVE-2020-13397)

  - freerdp: Out of bound read in update_recv could result
    in a crash (CVE-2020-11019)

  - freerdp: Integer overflow in VIDEO channel
    (CVE-2020-11038)

  - freerdp: Out of bound access in
    clear_decompress_subcode_rlex (CVE-2020-11040)

  - freerdp: Unchecked read of array offset in
    rdpsnd_recv_wave2_pdu (CVE-2020-11041)

  - freerdp: out of bound read in
    rfx_process_message_tileset (CVE-2020-11043)

  - freerdp: double free in
    update_read_cache_bitmap_v3_order function
    (CVE-2020-11044)

  - freerdp: out of bounds read in update_read_bitmap_data
    function (CVE-2020-11045)

  - freerdp: out of bounds seek in update_read_synchronize
    function could lead out of bounds read (CVE-2020-11046)

  - freerdp: out-of-bounds read could result in aborting the
    session (CVE-2020-11048)

  - freerdp: out-of-bound read of client memory that is then
    passed on to the protocol parser (CVE-2020-11049)

  - freerdp: stream out-of-bounds seek in
    rdp_read_font_capability_set could lead to out-of-bounds
    read (CVE-2020-11058)

  - freerdp: out-of-bounds read in cliprdr_read_format_list
    function (CVE-2020-11085)

  - freerdp: out-of-bounds read in
    ntlm_read_ntlm_v2_client_challenge function
    (CVE-2020-11086)

  - freerdp: out-of-bounds read in
    ntlm_read_AuthenticateMessage (CVE-2020-11087)

  - freerdp: out-of-bounds read in
    ntlm_read_NegotiateMessage (CVE-2020-11088)

  - freerdp: out-of-bounds read in irp functions
    (CVE-2020-11089)

  - freerdp: out-of-bounds read in gdi.c (CVE-2020-11522)

  - freerdp: out-of-bounds read in bitmap.c (CVE-2020-11525)

  - freerdp: Stream pointer out of bounds in
    update_recv_secondary_order could lead out of bounds
    read later (CVE-2020-11526)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2010&L=SCIENTIFIC-LINUX-ERRATA&P=14786
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa03362d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11522");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libwinpr-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freerdp-2.1.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freerdp-debuginfo-2.1.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freerdp-devel-2.1.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freerdp-libs-2.1.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwinpr-2.1.1-2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libwinpr-devel-2.1.1-2.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp / freerdp-debuginfo / freerdp-devel / freerdp-libs / etc");
}
