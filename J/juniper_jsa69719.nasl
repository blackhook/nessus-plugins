##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163761);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2022-22215");
  script_xref(name:"JSA", value:"JSA69719");
  script_xref(name:"IAVA", value:"2022-A-0280");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69719)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69719
advisory.

  - A Missing Release of File Descriptor or Handle after Effective Lifetime vulnerability in plugable
    authentication module (PAM) of Juniper Networks Junos OS and Junos OS Evolved allows a locally
    authenticated attacker with low privileges to cause a Denial of Service (DoS). It is possible that after
    the termination of a gRPC connection the respective/var/run/<pid>.env file is not getting deleted which if
    occurring repeatedly can cause inode exhaustion. Inode exhaustion can present itself in two different
    ways: 1. The following log message can be observed: host kernel: pid <pid> (<process>), uid <uid> inumber
    <number> on /.mount/var: out of inodes which by itself is a clear indication. 2. The following log message
    can be observed: host <process>[<pid>]: ... : No space left on device which is not deterministic and just
    a representation of a write error which could have several reasons. So the following check needs to be
    done: user@host> show system storage no-forwarding Filesystem Size Used Avail Capacity Mounted on
    /dev/ada1p1 475M 300M 137M 69% /.mount/var which indicates that the write error is not actually due to a
    lack of disk space. If either 1. or 2. has been confirmed, then the output of: user@host> file list
    /var/run/*.env | count need to be checked and if it indicates a high (>10000) number of files the system
    has been affected by this issue. This issue affects: Juniper Networks Junos OS All versions prior to
    19.1R3-S8; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S5; 19.4 versions prior to
    19.4R2-S6, 19.4R3-S7; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S5; 20.3
    versions prior to 20.3R3-S4; 20.4 versions prior to 20.4R3; 21.1 versions prior to 21.1R3; 21.2 versions
    prior to 21.2R2. Juniper Networks Junos OS Evolved All versions prior to 20.4R3-EVO; 21.1 versions prior
    to 21.1R3-S1-EVO; 21.2 versions prior to 21.2R1-S1-EVO, 21.2R2-EVO. (CVE-2022-22215)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-07-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-var-run-pid-env-files-are-potentially-not-deleted-during-termination-of-a-gRPC-connection-causing-inode-exhaustion-CVE-2022-22215
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5166ad7");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69719");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S6'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S5'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R2-S6'},
  {'min_ver':'19.4R3', 'fixed_ver':'19.4R3-S7'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R1'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S5'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S4'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3', 'fixed_display':'21.1R3, 21.1R3-S1-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R1-S1-EVO', 'fixed_display':'21.2R1-S1-EVO, 21.2R2, 21.2R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
