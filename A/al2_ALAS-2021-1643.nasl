##
# (C) Tenable Network Security, Inc.
#
# # @DEPRECATED@
#
# Disabled on 2021-05-31 due to Amazon pulling the previsouly published advisory.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1643.
##
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149869);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/11");

  script_cve_id(
    "CVE-2018-15686",
    "CVE-2018-16864",
    "CVE-2018-16866",
    "CVE-2018-16888",
    "CVE-2019-3815",
    "CVE-2019-6454",
    "CVE-2019-20386"
  );
  script_xref(name:"ALAS", value:"2021-1643");

  script_name(english:"Amazon Linux 2 : systemd (ALAS-2021-1643) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The version of systemd installed on the remote host is prior to 219-78. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1643 advisory.

  - A vulnerability in unit_deserialize of systemd allows an attacker to supply arbitrary state across systemd
    re-execution via NotifyAccess. This can be used to improperly influence systemd execution and possibly
    lead to root privilege escalation. Affected releases are systemd versions up to and including 239.
    (CVE-2018-15686)

  - An allocation of memory without limits, that could result in the stack clashing with another memory
    region, was discovered in systemd-journald when a program with long command line arguments calls syslog. A
    local attacker may use this flaw to crash systemd-journald or escalate his privileges. Versions through
    v240 are vulnerable. (CVE-2018-16864)

  - An out of bounds read was discovered in systemd-journald in the way it parses log messages that terminate
    with a colon ':'. A local attacker can use this flaw to disclose process memory data. Versions from v221
    to v239 are vulnerable. (CVE-2018-16866)

  - It was discovered systemd does not correctly check the content of PIDFile files before using it to kill
    processes. When a service is run from an unprivileged user (e.g. User field set in the service file), a
    local attacker who is able to write to the PIDFile of the mentioned service may use this flaw to trick
    systemd into killing other services and/or privileged processes. Versions before v237 are vulnerable.
    (CVE-2018-16888)

  - An issue was discovered in button_open in login/logind-button.c in systemd before 243. When executing the
    udevadm trigger command, a memory leak may occur. (CVE-2019-20386)

  - A memory leak was discovered in the backport of fixes for CVE-2018-16864 in Red Hat Enterprise Linux.
    Function dispatch_message_real() in journald-server.c does not free the memory allocated by
    set_iovec_field_free() to store the `_CMDLINE=` entry. A local attacker may use this flaw to make systemd-
    journald crash. This issue only affects versions shipped with Red Hat Enterprise since v219-62.2.
    (CVE-2019-3815)

  - An issue was discovered in sd-bus in systemd 239. bus_process_object() in libsystemd/sd-bus/bus-objects.c
    allocates a variable-length stack buffer for temporarily storing the object path of incoming D-Bus
    messages. An unprivileged local user can exploit this by sending a specially crafted message to PID1,
    causing the stack pointer to jump over the stack guard pages into an unmapped memory region and trigger a
    denial of service (systemd PID1 crash and kernel panic). (CVE-2019-6454)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1643.html"); # advisory removed
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-15686");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16866");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-16888");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-20386");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3815");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-6454");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15686");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

exit(0, 'This plugin has been deprecated due to Amazon pulling the previously published advisory.');
