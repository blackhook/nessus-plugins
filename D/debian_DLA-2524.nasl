#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2524-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144956);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2017-15108", "CVE-2020-25650", "CVE-2020-25651", "CVE-2020-25652", "CVE-2020-25653");

  script_name(english:"Debian DLA-2524-1 : spice-vdagent security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were discovered in spice-vdagent, a spice
guest agent for enchancing SPICE integeration and experience.

CVE-2017-15108

spice-vdagent does not properly escape save directory before passing
to shell, allowing local attacker with access to the session the agent
runs in to inject arbitrary commands to be executed.

CVE-2020-25650

A flaw was found in the way the spice-vdagentd daemon handled file
transfers from the host system to the virtual machine. Any
unprivileged local guest user with access to the UNIX domain socket
path `/run/spice-vdagentd/spice-vdagent-sock` could use this flaw to
perform a memory denial of service for spice-vdagentd or even other
processes in the VM system. The highest threat from this vulnerability
is to system availability. This flaw affects spice-vdagent versions
0.20 and previous versions.

CVE-2020-25651

A flaw was found in the SPICE file transfer protocol. File data from
the host system can end up in full or in parts in the client
connection of an illegitimate local user in the VM system. Active file
transfers from other users could also be interrupted, resulting in a
denial of service. The highest threat from this vulnerability is to
data confidentiality as well as system availability.

CVE-2020-25652

A flaw was found in the spice-vdagentd daemon, where it did not
properly handle client connections that can be established via the
UNIX domain socket in `/run/spice-vdagentd/spice-vdagent-sock`. Any
unprivileged local guest user could use this flaw to prevent
legitimate agents from connecting to the spice-vdagentd daemon,
resulting in a denial of service. The highest threat from this
vulnerability is to system availability. 

CVE-2020-25653

A race condition vulnerability was found in the way the spice-vdagentd
daemon handled new client connections. This flaw may allow an
unprivileged local guest user to become the active agent for
spice-vdagentd, possibly resulting in a denial of service or
information leakage from the host. The highest threat from this
vulnerability is to data confidentiality as well as system
availability.

For Debian 9 stretch, these problems have been fixed in version
0.17.0-1+deb9u1.

We recommend that you upgrade your spice-vdagent packages.

For the detailed security status of spice-vdagent please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/spice-vdagent

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/spice-vdagent"
  );
  # https://security-tracker.debian.org/tracker/source-package/spice-vdagent
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a05439c4"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected spice-vdagent package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25653");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spice-vdagent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"spice-vdagent", reference:"0.17.0-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
