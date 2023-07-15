#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-833-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97332);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-9888", "CVE-2014-9895", "CVE-2016-6786", "CVE-2016-6787", "CVE-2016-8405", "CVE-2017-5549", "CVE-2017-6001", "CVE-2017-6074");

  script_name(english:"Debian DLA-833-1 : linux security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or have other
impacts.

CVE-2014-9888

Russell King found that on ARM systems, memory allocated for DMA
buffers was mapped with executable permission. This made it easier to
exploit other vulnerabilities in the kernel.

CVE-2014-9895

Dan Carpenter found that the MEDIA_IOC_ENUM_LINKS ioctl on media
devices resulted in an information leak.

CVE-2016-6786 / CVE-2016-6787

It was discovered that the performance events subsystem does not
properly manage locks during certain migrations, allowing a local
attacker to escalate privileges. This can be mitigated by disabling
unprivileged use of performance events: sysctl
kernel.perf_event_paranoid=3

CVE-2016-8405

Peter Pi of Trend Micro discovered that the frame buffer video
subsystem does not properly check bounds while copying color maps to
userspace, causing a heap buffer out-of-bounds read, leading to
information disclosure.

CVE-2017-5549

It was discovered that the KLSI KL5KUSB105 serial USB device driver
could log the contents of uninitialised kernel memory, resulting in an
information leak.

CVE-2017-6001

Di Shen discovered a race condition between concurrent calls to the
performance events subsystem, allowing a local attacker to escalate
privileges. This flaw exists because of an incomplete fix of
CVE-2016-6786. This can be mitigated by disabling unprivileged use of
performance events: sysctl kernel.perf_event_paranoid=3

CVE-2017-6074

Andrey Konovalov discovered a use-after-free vulnerability in the DCCP
networking code, which could result in denial of service or local
privilege escalation. On systems that do not already have the dccp
module loaded, this can be mitigated by disabling it: echo >>
/etc/modprobe.d/disable-dccp.conf install dccp false

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.84-2.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.39-1+deb8u1 or earlier.

We recommend that you upgrade your linux packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00021.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.84-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
