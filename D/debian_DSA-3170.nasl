#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3170. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81449);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-7421", "CVE-2014-7822", "CVE-2014-8160", "CVE-2014-8559", "CVE-2014-9585", "CVE-2014-9644", "CVE-2014-9683", "CVE-2015-0239", "CVE-2015-1420", "CVE-2015-1421", "CVE-2015-1593");
  script_xref(name:"DSA", value:"3170");

  script_name(english:"Debian DSA-3170-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a denial of service, information leaks or privilege
escalation.

  - CVE-2013-7421 / CVE-2014-9644
    It was discovered that the Crypto API allowed
    unprivileged users to load arbitrary kernel modules. A
    local user can use this flaw to exploit vulnerabilities
    in modules that would not normally be loaded.

  - CVE-2014-7822
    Akira Fujita found that the splice() system call did not
    validate the given file offset and length. A local
    unprivileged user can use this flaw to cause filesystem
    corruption on ext4 filesystems, or possibly other
    effects.

  - CVE-2014-8160
    Florian Westphal discovered that a netfilter
    (iptables/ip6tables) rule accepting packets to a
    specific SCTP, DCCP, GRE or UDPlite port/endpoint could
    result in incorrect connection tracking state. If only
    the generic connection tracking module (nf_conntrack)
    was loaded, and not the protocol-specific connection
    tracking module, this would allow access to any
    port/endpoint of the specified protocol.

  - CVE-2014-8559
    It was found that kernel functions that iterate over a
    directory tree can dead-lock or live-lock in case some
    of the directory entries were recently deleted or
    dropped from the cache. A local unprivileged user can
    use this flaw for denial of service.

  - CVE-2014-9585
    Andy Lutomirski discovered that address randomisation
    for the vDSO in 64-bit processes is extremely biased. A
    local unprivileged user could potentially use this flaw
    to bypass the ASLR protection mechanism.

  - CVE-2014-9683
    Dmitry Chernenkov discovered that eCryptfs writes past
    the end of the allocated buffer during encrypted
    filename decoding, resulting in local denial of service.

  - CVE-2015-0239
    It was found that KVM did not correctly emulate the x86
    SYSENTER instruction. An unprivileged user within a
    guest system that has not enabled SYSENTER, for example
    because the emulated CPU vendor is AMD, could
    potentially use this flaw to cause a denial of service
    or privilege escalation in that guest.

  - CVE-2015-1420
    It was discovered that the open_by_handle_at() system
    call reads the handle size from user memory a second
    time after validating it. A local user with the
    CAP_DAC_READ_SEARCH capability could use this flaw for
    privilege escalation.

  - CVE-2015-1421
    It was found that the SCTP implementation could free an
    authentication state while it was still in use,
    resulting in heap corruption. This could allow remote
    users to cause a denial of service or privilege
    escalation.

  - CVE-2015-1593
    It was found that address randomisation for the initial
    stack in 64-bit processes was limited to 20 rather than
    22 bits of entropy. A local unprivileged user could
    potentially use this flaw to bypass the ASLR protection
    mechanism."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-7421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-7822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2015/dsa-3170"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the linux packages.

For the stable distribution (wheezy), these problems have been fixed
in version 3.2.65-1+deb7u2. Additionally this update fixes regressions
introduced in versions 3.2.65-1 and 3.2.65-1+deb7u1.

For the upcoming stable distribution (jessie), these problems will be
fixed soon (a subset is fixed already)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");
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
if (deb_check(release:"7.0", prefix:"linux", reference:"3.2.65-1+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
