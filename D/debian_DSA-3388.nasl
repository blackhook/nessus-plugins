#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3388. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86682);
  script_version("2.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-9750", "CVE-2014-9751", "CVE-2015-3405", "CVE-2015-5146", "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7850", "CVE-2015-7852", "CVE-2015-7855", "CVE-2015-7871");
  script_xref(name:"DSA", value:"3388");
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"Debian DSA-3388-1 : ntp - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in the Network Time Protocol
daemon and utility programs :

  - CVE-2015-5146
    A flaw was found in the way ntpd processed certain
    remote configuration packets. An attacker could use a
    specially crafted package to cause ntpd to crash if :

    - ntpd enabled remote configuration
    - The attacker had the knowledge of the configuration
      password

    - The attacker had access to a computer entrusted to
      perform remote configuration

      Note that remote configuration is disabled by default
      in NTP.

  - CVE-2015-5194
    It was found that ntpd could crash due to an
    uninitialized variable when processing malformed
    logconfig configuration commands.

  - CVE-2015-5195
    It was found that ntpd exits with a segmentation fault
    when a statistics type that was not enabled during
    compilation (e.g. timingstats) is referenced by the
    statistics or filegen configuration command.

  - CVE-2015-5219
    It was discovered that sntp program would hang in an
    infinite loop when a crafted NTP packet was received,
    related to the conversion of the precision value in the
    packet to double.

  - CVE-2015-5300
    It was found that ntpd did not correctly implement the
    -g option :

  Normally, ntpd exits with a message to the system log if the offset
  exceeds the panic threshold, which is 1000 s by default. This option
  allows the time to be set to any value without restriction; however,
  this can happen only once. If the threshold is exceeded after that,
  ntpd will exit with a message to the system log. This option can be
  used with the -q and -x options.

  ntpd could actually step the clock multiple times by more than the
  panic threshold if its clock discipline doesn't have enough time to
  reach the sync state and stay there for at least one update. If a
  man-in-the-middle attacker can control the NTP traffic since ntpd
  was started (or maybe up to 15-30 minutes after that), they can
  prevent the client from reaching the sync state and force it to step
  its clock by any amount any number of times, which can be used by
  attackers to expire certificates, etc.

  This is contrary to what the documentation says. Normally, the
  assumption is that an MITM attacker can step the clock more than the
  panic threshold only once when ntpd starts and to make a larger
  adjustment the attacker has to divide it into multiple smaller
  steps, each taking 15 minutes, which is slow.

  - CVE-2015-7691, CVE-2015-7692, CVE-2015-7702
    It was found that the fix for CVE-2014-9750 was
    incomplete: three issues were found in the value length
    checks in ntp_crypto.c, where a packet with particular
    autokey operations that contained malicious data was not
    always being completely validated. Receipt of these
    packets can cause ntpd to crash.

  - CVE-2015-7701
    A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If
    ntpd is configured to use autokey authentication, an
    attacker could send packets to ntpd that would, after
    several days of ongoing attack, cause it to run out of
    memory.

  - CVE-2015-7703
    Miroslav Lichvar of Red Hat found that the :config
    command can be used to set the pidfile and driftfile
    paths without any restrictions. A remote attacker could
    use this flaw to overwrite a file on the file system
    with a file containing the pid of the ntpd process
    (immediately) or the current estimated drift of the
    system clock (in hourly intervals). For example :

  ntpq -c ':config pidfile /tmp/ntp.pid'ntpq -c ':config driftfile
  /tmp/ntp.drift'

  In Debian ntpd is configured to drop root privileges, which limits
  the impact of this issue.

  - CVE-2015-7704
    If ntpd as an NTP client receives a Kiss-of-Death (KoD)
    packet from the server to reduce its polling rate, it
    doesn't check if the originate timestamp in the reply
    matches the transmit timestamp from its request. An
    off-path attacker can send a crafted KoD packet to the
    client, which will increase the client's polling
    interval to a large value and effectively disable
    synchronization with the server.

  - CVE-2015-7850
    An exploitable denial of service vulnerability exists in
    the remote configuration functionality of the Network
    Time Protocol. A specially crafted configuration file
    could cause an endless loop resulting in a denial of
    service. An attacker could provide a malicious
    configuration file to trigger this vulnerability.

  - CVE-2015-7852
    A potential off by one vulnerability exists in the
    cookedprint functionality of ntpq. A specially crafted
    buffer could cause a buffer overflow potentially
    resulting in null byte being written out of bounds.

  - CVE-2015-7855
    It was found that NTP's decodenetnum() would abort with
    an assertion failure when processing a mode 6 or mode 7
    packet containing an unusually long data value where a
    network address was expected. This could allow an
    authenticated attacker to crash ntpd.

  - CVE-2015-7871
    An error handling logic error exists within ntpd that
    manifests due to improper error condition handling
    associated with certain crypto-NAK packets. An
    unauthenticated, off-path attacker can force ntpd
    processes on targeted servers to peer with time sources
    of the attacker's choosing by transmitting symmetric
    active crypto-NAK packets to ntpd. This attack bypasses
    the authentication typically required to establish a
    peer association and allows an attacker to make
    arbitrary changes to system time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ntp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ntp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the ntp packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1:4.2.6.p5+dfsg-2+deb7u6.

For the stable distribution (jessie), these problems have been fixed
in version 1:4.2.6.p5+dfsg-7+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"ntp", reference:"1:4.2.6.p5+dfsg-2+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ntp-doc", reference:"1:4.2.6.p5+dfsg-2+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"ntpdate", reference:"1:4.2.6.p5+dfsg-2+deb7u6")) flag++;
if (deb_check(release:"8.0", prefix:"ntp", reference:"1:4.2.6.p5+dfsg-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntp-doc", reference:"1:4.2.6.p5+dfsg-7+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"ntpdate", reference:"1:4.2.6.p5+dfsg-7+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
