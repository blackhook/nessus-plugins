#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1923-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128881);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-3908", "CVE-2015-6240", "CVE-2018-10875", "CVE-2019-10156");
  script_bugtraq_id(75921);

  script_name(english:"Debian DLA-1923-1 : ansible security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Ansible, a configuration
management, deployment, and task execution system.

CVE-2015-3908

A potential man-in-the-middle attack associated with insusfficient
X.509 certificate verification. Ansible did not verify that the server
hostname matches a domain name in the subject's Common Name (CN) or
subjectAltName field of the X.509 certificate, which allows
man-in-the-middle attackers to spoof SSL servers via an arbitrary
valid certificate.

CVE-2015-6240

A symlink attack that allows local users to escape a restricted
environment (chroot or jail) via a symlink attack.

CVE-2018-10875

A fix potential arbitrary code execution resulting from reading
ansible.cfg from a world-writable current working directory. This
condition now causes ansible to emit a warning and ignore the
ansible.cfg in the world-writable current working directory.

CVE-2019-10156

Information disclosure through unexpected variable substitution.

For Debian 8 'Jessie', these problems have been fixed in version
1.7.2+dfsg-2+deb8u2.

We recommend that you upgrade your ansible packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ansible"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible-fireball");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible-node-fireball");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"ansible", reference:"1.7.2+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ansible-doc", reference:"1.7.2+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ansible-fireball", reference:"1.7.2+dfsg-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ansible-node-fireball", reference:"1.7.2+dfsg-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
