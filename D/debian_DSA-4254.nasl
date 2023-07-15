#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4254. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111316);
  script_version("1.4");
  script_cvs_date("Date: 2018/11/13 12:30:47");

  script_cve_id("CVE-2018-10995", "CVE-2018-7033");
  script_xref(name:"DSA", value:"4254");

  script_name(english:"Debian DSA-4254-1 : slurm-llnl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the Simple Linux Utility
for Resource Management (SLURM), a cluster resource management and job
scheduling system. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2018-7033
    Incomplete sanitization of user-provided text strings
    could lead to SQL injection attacks against slurmdbd.

  - CVE-2018-10995
    Insecure handling of user_name and gid fields leading to
    improper authentication handling."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=893044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=900548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-7033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-10995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/slurm-llnl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/slurm-llnl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4254"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the slurm-llnl packages.

For the stable distribution (stretch), these problems have been fixed
in version 16.05.9-1+deb9u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slurm-llnl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libpam-slurm", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi0", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi0-dbg", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi0-dev", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi2-0", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi2-0-dbg", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpmi2-0-dev", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libslurm-dev", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libslurm-perl", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libslurm30", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libslurm30-dbg", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libslurmdb-dev", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libslurmdb-perl", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libslurmdb30", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libslurmdb30-dbg", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-client", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-client-dbg", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-client-emulator", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-llnl", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-llnl-slurmdbd", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-basic-plugins", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-basic-plugins-dbg", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-basic-plugins-dev", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-doc", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-emulator", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurm-wlm-torque", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurmctld", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurmctld-dbg", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurmd", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurmd-dbg", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurmdbd", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"slurmdbd-dbg", reference:"16.05.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"sview", reference:"16.05.9-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
