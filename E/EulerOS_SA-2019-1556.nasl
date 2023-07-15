#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125009);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-9294",
    "CVE-2014-9750",
    "CVE-2015-5195",
    "CVE-2015-5300",
    "CVE-2015-7691",
    "CVE-2015-7701",
    "CVE-2015-7703",
    "CVE-2015-7852",
    "CVE-2015-7974",
    "CVE-2015-7978",
    "CVE-2015-7979",
    "CVE-2016-2516",
    "CVE-2016-2518",
    "CVE-2016-4955",
    "CVE-2016-4956",
    "CVE-2016-7429",
    "CVE-2016-7433",
    "CVE-2016-9311",
    "CVE-2017-6463",
    "CVE-2018-12327"
  );
  script_bugtraq_id(
    71762
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : ntp (EulerOS-SA-2019-1556)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ntp packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - A vulnerability was discovered in the NTP server's
    parsing of configuration directives. A remote,
    authenticated attacker could cause ntpd to crash by
    sending a crafted message.(CVE-2017-6463)

  - ntpd in NTP 4.x before 4.2.8p8, when autokey is
    enabled, allows remote attackers to cause a denial of
    service (peer-variable clearing and association outage)
    by sending (1) a spoofed crypto-NAK packet or (2) a
    packet with an incorrect MAC value at a certain
    time.(CVE-2016-4955)

  - The ntpq and ntpdc command-line utilities that are part
    of ntp package are vulnerable to stack-based buffer
    overflow via crafted hostname. Applications using these
    vulnerable utilities with an untrusted input may be
    potentially exploited, resulting in a crash or
    arbitrary code execution under privileges of that
    application.(CVE-2018-12327)

  - NTP before 4.2.8p7 and 4.3.x before 4.3.92, when mode7
    is enabled, allows remote attackers to cause a denial
    of service (ntpd abort) by using the same IP address
    multiple times in an unconfig directive.(CVE-2016-2516)

  - A flaw was found in the way NTP verified trusted keys
    during symmetric key authentication. An authenticated
    client (A) could use this flaw to modify a packet sent
    between a server (B) and a client (C) using a key that
    is different from the one known to the client
    (A).(CVE-2015-7974)

  - A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If
    ntpd was configured to use autokey authentication, an
    attacker could send packets to ntpd that would, after
    several days of ongoing attack, cause it to run out of
    memory.(CVE-2015-7701)

  - An out-of-bounds access flaw was found in the way ntpd
    processed certain packets. An authenticated attacker
    could use a crafted packet to create a peer association
    with hmode of 7 and larger, which could potentially
    (although highly unlikely) cause ntpd to
    crash.(CVE-2016-2518)

  - A stack-based buffer overflow was found in the way the
    NTP autokey protocol was implemented. When an NTP
    client decrypted a secret received from an NTP server,
    it could cause that client to crash.(CVE-2014-9750)

  - It was found that NTP's :config command could be used
    to set the pidfile and driftfile paths without any
    restrictions. A remote attacker could use this flaw to
    overwrite a file on the file system with a file
    containing the pid of the ntpd process (immediately) or
    the current estimated drift of the system clock (in
    hourly intervals).(CVE-2015-7703)

  - A flaw was found in the way ntpd running on a host with
    multiple network interfaces handled certain server
    responses. A remote attacker could use this flaw which
    would cause ntpd to not synchronize with the
    source.(CVE-2016-7429)

  - A flaw was found in the way ntpd implemented the trap
    service. A remote attacker could send a specially
    crafted packet to cause a null pointer dereference that
    will crash ntpd, resulting in a denial of
    service.(CVE-2016-9311)

  - It was found that ntp-keygen used a weak method for
    generating MD5 keys. This could possibly allow an
    attacker to guess generated MD5 keys that could then be
    used to spoof an NTP client or server. Note: it is
    recommended to regenerate any MD5 keys that had
    explicitly been generated with ntp-keygen the default
    installation does not contain such keys.(CVE-2014-9294)

  - It was found that when NTP was configured in broadcast
    mode, a remote attacker could broadcast packets with
    bad authentication to all clients. The clients, upon
    receiving the malformed packets, would break the
    association with the broadcast server, causing them to
    become out of sync over a longer period of
    time.(CVE-2015-7979)

  - A flaw was found in the way ntpd calculated the root
    delay. A remote attacker could send a specially-crafted
    spoofed packet to cause denial of service or in some
    special cases even crash.(CVE-2016-7433)

  - It was found that the fix for CVE-2014-9750 was
    incomplete: three issues were found in the value length
    checks in NTP's ntp_crypto.c, where a packet with
    particular autokey operations that contained malicious
    data was not always being completely validated. A
    remote attacker could use a specially crafted NTP
    packet to crash ntpd.(CVE-2015-7691)

  - It was found that ntpd did not correctly implement the
    threshold limitation for the '-g' option, which is used
    to set the time without any restrictions. A
    man-in-the-middle attacker able to intercept NTP
    traffic between a connecting client and an NTP server
    could use this flaw to force that client to make
    multiple steps larger than the panic threshold,
    effectively changing the time to an arbitrary value at
    any time.(CVE-2015-5300)

  - It was found that ntpd would exit with a segmentation
    fault when a statistics type that was not enabled
    during compilation (e.g. timingstats) was referenced by
    the statistics or filegen configuration
    command.(CVE-2015-5195)

  - An off-by-one flaw, leading to a buffer overflow, was
    found in cookedprint functionality of ntpq. A specially
    crafted NTP packet could potentially cause ntpq to
    crash.(CVE-2015-7852)

  - ntpd in NTP 4.x before 4.2.8p8 allows remote attackers
    to cause a denial of service (interleaved-mode
    transition and time change) via a spoofed broadcast
    packet. NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2016-1548.(CVE-2016-4956)

  - A stack-based buffer overflow flaw was found in the way
    ntpd processed 'ntpdc reslist' commands that queried
    restriction lists with a large amount of entries. A
    remote attacker could use this flaw to crash
    ntpd.(CVE-2015-7978)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1556
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05f63142");
  script_set_attribute(attribute:"solution", value:
"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12327");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ntpdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sntp");
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

pkgs = ["ntp-4.2.6p5-28.h8",
        "ntpdate-4.2.6p5-28.h8",
        "sntp-4.2.6p5-28.h8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
