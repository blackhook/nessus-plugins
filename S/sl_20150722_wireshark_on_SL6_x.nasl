#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85208);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-8710", "CVE-2014-8711", "CVE-2014-8712", "CVE-2014-8713", "CVE-2014-8714", "CVE-2015-0562", "CVE-2015-0564", "CVE-2015-2189", "CVE-2015-2191");

  script_name(english:"Scientific Linux Security Update : wireshark on SL6.x i386/x86_64 (20150722)");
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
"Several denial of service flaws were found in Wireshark. Wireshark
could crash or stop responding if it read a malformed packet off a
network, or opened a malicious dump file. (CVE-2014-8714,
CVE-2014-8712, CVE-2014-8713, CVE-2014-8711, CVE-2014-8710,
CVE-2015-0562, CVE-2015-0564, CVE-2015-2189, CVE-2015-2191)

This update also fixes the following bugs :

  - Previously, the Wireshark tool did not support Advanced
    Encryption Standard Galois/Counter Mode (AES-GCM)
    cryptographic algorithm. As a consequence, AES-GCM was
    not decrypted. Support for AES-GCM has been added to
    Wireshark, and AES-GCM is now correctly decrypted.

  - Previously, when installing the system using the
    kickstart method, a dependency on the shadow-utils
    packages was missing from the wireshark packages, which
    could cause the installation to fail with a 'bad
    scriptlet' error message. With this update, shadow-utils
    are listed as required in the wireshark packages spec
    file, and kickstart installation no longer fails.

  - Prior to this update, the Wireshark tool could not
    decode types of elliptic curves in Datagram Transport
    Layer Security (DTLS) Client Hello. Consequently,
    Wireshark incorrectly displayed elliptic curves types as
    data. A patch has been applied to address this bug, and
    Wireshark now decodes elliptic curves types properly.

  - Previously, a dependency on the gtk2 packages was
    missing from the wireshark packages. As a consequence,
    the Wireshark tool failed to start under certain
    circumstances due to an unresolved symbol,
    'gtk_combo_box_text_new_with_entry', which was added in
    gtk version 2.24. With this update, a dependency on gtk2
    has been added, and Wireshark now always starts as
    expected.

In addition, this update adds the following enhancements :

  - With this update, the Wireshark tool supports process
    substitution, which feeds the output of a process (or
    processes) into the standard input of another process
    using the '<(command_list)' syntax. When using process
    substitution with large files as input, Wireshark failed
    to decode such input.

  - Wireshark has been enhanced to enable capturing packets
    with nanosecond time stamp precision, which allows
    better analysis of recorded network traffic.

All running instances of Wireshark must be restarted for the update to
take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=4657
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36c0f664"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"wireshark-1.8.10-17.el6")) flag++;
if (rpm_check(release:"SL6", reference:"wireshark-debuginfo-1.8.10-17.el6")) flag++;
if (rpm_check(release:"SL6", reference:"wireshark-devel-1.8.10-17.el6")) flag++;
if (rpm_check(release:"SL6", reference:"wireshark-gnome-1.8.10-17.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-devel / wireshark-gnome");
}
