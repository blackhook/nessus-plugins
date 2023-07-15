#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2202-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136367);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-14846", "CVE-2020-1733", "CVE-2020-1739", "CVE-2020-1740");
  script_xref(name:"IAVB", value:"2019-B-0092-S");

  script_name(english:"Debian DLA-2202-1 : ansible security update");
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

CVE-2019-14846

Ansible was logging at the DEBUG level which lead to a disclosure of
credentials if a plugin used a library that logged credentials at the
DEBUG level. This flaw does not affect Ansible modules, as those are
executed in a separate process.

CVE-2020-1733

A race condition flaw was found when running a playbook with an
unprivileged become user. When Ansible needs to run a module with
become user, the temporary directory is created in /var/tmp. This
directory is created with 'umask 77 && mkdir -p dir'; this operation
does not fail if the directory already exists and is owned by another
user. An attacker could take advantage to gain control of the become
user as the target directory can be retrieved by iterating
'/proc/pid/cmdline'.

CVE-2020-1739

A flaw was found when a password is set with the argument 'password'
of svn module, it is used on svn command line, disclosing to other
users within the same node. An attacker could take advantage by
reading the cmdline file from that particular PID on the procfs.

CVE-2020-1740

A flaw was found when using Ansible Vault for editing encrypted files.
When a user executes 'ansible-vault edit', another user on the same
computer can read the old and new secret, as it is created in a
temporary file with mkstemp and the returned file descriptor is closed
and the method write_data is called to write the existing secret in
the file. This method will delete the file before recreating it
insecurely.

For Debian 8 'Jessie', these problems have been fixed in version
1.7.2+dfsg-2+deb8u3.

We recommend that you upgrade your ansible packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/05/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ansible"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1733");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible-fireball");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible-node-fireball");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"ansible", reference:"1.7.2+dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"ansible-doc", reference:"1.7.2+dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"ansible-fireball", reference:"1.7.2+dfsg-2+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"ansible-node-fireball", reference:"1.7.2+dfsg-2+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
