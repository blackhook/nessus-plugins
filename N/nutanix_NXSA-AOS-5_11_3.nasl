#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164602);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/14");

  script_cve_id(
    "CVE-2018-7755",
    "CVE-2018-8087",
    "CVE-2018-9363",
    "CVE-2018-9516",
    "CVE-2018-9517",
    "CVE-2018-10853",
    "CVE-2018-12207",
    "CVE-2018-13053",
    "CVE-2018-13093",
    "CVE-2018-13094",
    "CVE-2018-13095",
    "CVE-2018-14625",
    "CVE-2018-14734",
    "CVE-2018-15594",
    "CVE-2018-16658",
    "CVE-2018-16871",
    "CVE-2018-16881",
    "CVE-2018-16884",
    "CVE-2018-16885",
    "CVE-2018-18281",
    "CVE-2018-20856",
    "CVE-2019-0154",
    "CVE-2019-0155",
    "CVE-2019-1125",
    "CVE-2019-2945",
    "CVE-2019-2949",
    "CVE-2019-2962",
    "CVE-2019-2964",
    "CVE-2019-2973",
    "CVE-2019-2975",
    "CVE-2019-2978",
    "CVE-2019-2981",
    "CVE-2019-2983",
    "CVE-2019-2987",
    "CVE-2019-2988",
    "CVE-2019-2989",
    "CVE-2019-2992",
    "CVE-2019-2999",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-3846",
    "CVE-2019-3882",
    "CVE-2019-3900",
    "CVE-2019-5489",
    "CVE-2019-5544",
    "CVE-2019-7222",
    "CVE-2019-9500",
    "CVE-2019-9506",
    "CVE-2019-10126",
    "CVE-2019-11085",
    "CVE-2019-11135",
    "CVE-2019-11599",
    "CVE-2019-11729",
    "CVE-2019-11745",
    "CVE-2019-11810",
    "CVE-2019-11811",
    "CVE-2019-11833",
    "CVE-2019-13734",
    "CVE-2019-14287",
    "CVE-2019-14816",
    "CVE-2019-14821",
    "CVE-2019-14835",
    "CVE-2019-14895",
    "CVE-2019-14898",
    "CVE-2019-14901",
    "CVE-2019-15239",
    "CVE-2019-17133",
    "CVE-2019-18397",
    "CVE-2019-18634",
    "CVE-2020-2583",
    "CVE-2020-2590",
    "CVE-2020-2593",
    "CVE-2020-2601",
    "CVE-2020-2604",
    "CVE-2020-2654",
    "CVE-2020-2659"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.11.3)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.11.3. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.11.3 advisory.

  - A flaw was found in the way Linux kernel KVM hypervisor before 4.18 emulated instructions such as
    sgdt/sidt/fxsave/fxrstor. It did not check current privilege(CPL) level while emulating unprivileged
    instructions. An unprivileged guest user/process could use this flaw to potentially escalate privileges
    inside guest. (CVE-2018-10853)

  - Improper invalidation for page table updates by a virtual guest operating system for multiple Intel(R)
    Processors may allow an authenticated user to potentially enable denial of service of the host system via
    local access. (CVE-2018-12207)

  - The alarm_timer_nsleep function in kernel/time/alarmtimer.c in the Linux kernel through 4.17.3 has an
    integer overflow via a large relative timeout because ktime_add_safe is not used. (CVE-2018-13053)

  - An issue was discovered in fs/xfs/xfs_icache.c in the Linux kernel through 4.17.3. There is a NULL pointer
    dereference and panic in lookup_slow() on a NULL inode->i_ops pointer when doing pathwalks on a corrupted
    xfs image. This occurs because of a lack of proper validation that cached inodes are free during
    allocation. (CVE-2018-13093)

  - An issue was discovered in fs/xfs/libxfs/xfs_attr_leaf.c in the Linux kernel through 4.17.3. An OOPS may
    occur for a corrupted xfs image after xfs_da_shrink_inode() is called with a NULL bp. (CVE-2018-13094)

  - An issue was discovered in fs/xfs/libxfs/xfs_inode_buf.c in the Linux kernel through 4.17.3. A denial of
    service (memory corruption and BUG) can occur for a corrupted xfs image upon encountering an inode that is
    in extent format, but has more extents than fit in the inode fork. (CVE-2018-13095)

  - A flaw was found in the Linux Kernel where an attacker may be able to have an uncontrolled read to kernel-
    memory from within a vm guest. A race condition between connect() and close() function may allow an
    attacker using the AF_VSOCK protocol to gather a 4 byte information leak or possibly intercept or corrupt
    AF_VSOCK messages destined to other clients. (CVE-2018-14625)

  - drivers/infiniband/core/ucma.c in the Linux kernel through 4.17.11 allows ucma_leave_multicast to access a
    certain data structure after a cleanup step in ucma_process_join, which allows attackers to cause a denial
    of service (use-after-free). (CVE-2018-14734)

  - arch/x86/kernel/paravirt.c in the Linux kernel before 4.18.1 mishandles certain indirect calls, which
    makes it easier for attackers to conduct Spectre-v2 attacks against paravirtual guests. (CVE-2018-15594)

  - An issue was discovered in the Linux kernel before 4.18.6. An information leak in cdrom_ioctl_drive_status
    in drivers/cdrom/cdrom.c could be used by local attackers to read kernel memory because a cast from
    unsigned long to int interferes with bounds checking. This is similar to CVE-2018-10940. (CVE-2018-16658)

  - A flaw was found in the Linux kernel's NFS implementation, all versions 3.x and all versions 4.x up to
    4.20. An attacker, who is able to mount an exported NFS filesystem, is able to trigger a null pointer
    dereference by using an invalid NFS sequence. This can panic the machine and deny access to the NFS
    server. Any outstanding disk writes to the NFS server will be lost. (CVE-2018-16871)

  - A denial of service vulnerability was found in rsyslog in the imptcp module. An attacker could send a
    specially crafted message to the imptcp socket, which would cause rsyslog to crash. Versions before 8.27.0
    are vulnerable. (CVE-2018-16881)

  - A flaw was found in the Linux kernel's NFS41+ subsystem. NFS41+ shares mounted in different network
    namespaces at the same time can make bc_svc_process() use wrong back-channel IDs and cause a use-after-
    free vulnerability. Thus a malicious container user can cause a host kernel memory corruption and a system
    panic. Due to the nature of the flaw, privilege escalation cannot be fully ruled out. (CVE-2018-16884)

  - A flaw was found in the Linux kernel that allows the userspace to call memcpy_fromiovecend() and similar
    functions with a zero offset and buffer length which causes the read beyond the buffer boundaries, in
    certain cases causing a memory access fault and a system halt by accessing invalid memory address. This
    issue only affects kernel version 3.10.x as shipped with Red Hat Enterprise Linux 7. (CVE-2018-16885)

  - Since Linux kernel version 3.2, the mremap() syscall performs TLB flushes after dropping pagetable locks.
    If a syscall such as ftruncate() removes entries from the pagetables of a task that is in the middle of
    mremap(), a stale TLB entry can remain for a short time that permits access to a physical page after it
    has been released back to the page allocator and reused. This is fixed in the following kernel versions:
    4.9.135, 4.14.78, 4.18.16, 4.19. (CVE-2018-18281)

  - An issue was discovered in the Linux kernel before 4.18.7. In block/blk-core.c, there is an
    __blk_drain_queue() use-after-free because a certain error case is mishandled. (CVE-2018-20856)

  - An issue was discovered in the fd_locked_ioctl function in drivers/block/floppy.c in the Linux kernel
    through 4.15.7. The floppy driver will copy a kernel pointer to user memory in response to the FDGETPRM
    ioctl. An attacker can send the FDGETPRM ioctl and use the obtained kernel pointer to discover the
    location of kernel code and data and bypass kernel security protections such as KASLR. (CVE-2018-7755)

  - Memory leak in the hwsim_new_radio_nl function in drivers/net/wireless/mac80211_hwsim.c in the Linux
    kernel through 4.15.9 allows local users to cause a denial of service (memory consumption) by triggering
    an out-of-array error case. (CVE-2018-8087)

  - In the hidp_process_report in bluetooth, there is an integer overflow. This could lead to an out of bounds
    write with no additional execution privileges needed. User interaction is not needed for exploitation.
    Product: Android Versions: Android kernel Android ID: A-65853588 References: Upstream kernel.
    (CVE-2018-9363)

  - In hid_debug_events_read of drivers/hid/hid-debug.c, there is a possible out of bounds write due to a
    missing bounds check. This could lead to local escalation of privilege with System execution privileges
    needed. User interaction is not needed for exploitation. Product: Android Versions: Android kernel Android
    ID: A-71361580. (CVE-2018-9516)

  - In pppol2tp_connect, there is possible memory corruption due to a use after free. This could lead to local
    escalation of privilege with System execution privileges needed. User interaction is not needed for
    exploitation. Product: Android. Versions: Android kernel. Android ID: A-38159931. (CVE-2018-9517)

  - Insufficient access control in subsystem for Intel (R) processor graphics in 6th, 7th, 8th and 9th
    Generation Intel(R) Core(TM) Processor Families; Intel(R) Pentium(R) Processor J, N, Silver and Gold
    Series; Intel(R) Celeron(R) Processor J, N, G3900 and G4900 Series; Intel(R) Atom(R) Processor A and E3900
    Series; Intel(R) Xeon(R) Processor E3-1500 v5 and v6 and E-2100 Processor Families may allow an
    authenticated user to potentially enable denial of service via local access. (CVE-2019-0154)

  - Insufficient access control in a subsystem for Intel (R) processor graphics in 6th, 7th, 8th and 9th
    Generation Intel(R) Core(TM) Processor Families; Intel(R) Pentium(R) Processor J, N, Silver and Gold
    Series; Intel(R) Celeron(R) Processor J, N, G3900 and G4900 Series; Intel(R) Atom(R) Processor A and E3900
    Series; Intel(R) Xeon(R) Processor E3-1500 v5 and v6, E-2100 and E-2200 Processor Families; Intel(R)
    Graphics Driver for Windows before 26.20.100.6813 (DCH) or 26.20.100.6812 and before 21.20.x.5077
    (aka15.45.5077), i915 Linux Driver for Intel(R) Processor Graphics before versions 5.4-rc7, 5.3.11,
    4.19.84, 4.14.154, 4.9.201, 4.4.201 may allow an authenticated user to potentially enable escalation of
    privilege via local access. (CVE-2019-0155)

  - A flaw was found in the Linux kernel. A heap based buffer overflow in mwifiex_uap_parse_tail_ies function
    in drivers/net/wireless/marvell/mwifiex/ie.c might lead to memory corruption and possibly other
    consequences. (CVE-2019-10126)

  - Insufficient input validation in Kernel Mode Driver in Intel(R) i915 Graphics for Linux before version 5.0
    may allow an authenticated user to potentially enable escalation of privilege via local access.
    (CVE-2019-11085)

  - TSX Asynchronous Abort condition on some CPUs utilizing speculative execution may allow an authenticated
    user to potentially enable information disclosure via a side channel with local access. (CVE-2019-11135)

  - An information disclosure vulnerability exists when certain central processing units (CPU) speculatively
    access memory, aka 'Windows Kernel Information Disclosure Vulnerability'. This CVE ID is unique from
    CVE-2019-1071, CVE-2019-1073. (CVE-2019-1125)

  - The coredump implementation in the Linux kernel before 5.0.10 does not use locking or other mechanisms to
    prevent vma layout or vma flags changes while it runs, which allows local users to obtain sensitive
    information, cause a denial of service, or possibly have unspecified other impact by triggering a race
    condition with mmget_not_zero or get_task_mm calls. This is related to fs/userfaultfd.c, mm/mmap.c,
    fs/proc/task_mmu.c, and drivers/infiniband/core/uverbs_main.c. (CVE-2019-11599)

  - Empty or malformed p256-ECDH public keys may trigger a segmentation fault due values being improperly
    sanitized before being copied into memory and used. This vulnerability affects Firefox ESR < 60.8, Firefox
    < 68, and Thunderbird < 60.8. (CVE-2019-11729)

  - When encrypting with a block cipher, if a call to NSC_EncryptUpdate was made with data smaller than the
    block size, a small out of bounds write could occur. This could have caused heap corruption and a
    potentially exploitable crash. This vulnerability affects Thunderbird < 68.3, Firefox ESR < 68.3, and
    Firefox < 71. (CVE-2019-11745)

  - An issue was discovered in the Linux kernel before 5.0.7. A NULL pointer dereference can occur when
    megasas_create_frame_pool() fails in megasas_alloc_cmds() in drivers/scsi/megaraid/megaraid_sas_base.c.
    This causes a Denial of Service, related to a use-after-free. (CVE-2019-11810)

  - An issue was discovered in the Linux kernel before 5.0.4. There is a use-after-free upon attempted read
    access to /proc/ioports after the ipmi_si module is removed, related to drivers/char/ipmi/ipmi_si_intf.c,
    drivers/char/ipmi/ipmi_si_mem_io.c, and drivers/char/ipmi/ipmi_si_port_io.c. (CVE-2019-11811)

  - fs/ext4/extents.c in the Linux kernel through 5.1.2 does not zero out the unused memory region in the
    extent tree block, which might allow local users to obtain sensitive information by reading uninitialized
    data in the filesystem. (CVE-2019-11833)

  - Out of bounds write in SQLite in Google Chrome prior to 79.0.3945.79 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2019-13734)

  - In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy
    blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user
    ID. For example, this allows bypass of !root configuration, and USER= logging, for a sudo -u
    \#$((0xffffffff)) command. (CVE-2019-14287)

  - There is heap-based buffer overflow in kernel, all versions up to, excluding 5.3, in the marvell wifi chip
    driver in Linux kernel, that allows local users to cause a denial of service(system crash) or possibly
    execute arbitrary code. (CVE-2019-14816)

  - An out-of-bounds access issue was found in the Linux kernel, all versions through 5.3, in the way Linux
    kernel's KVM hypervisor implements the Coalesced MMIO write operation. It operates on an MMIO ring buffer
    'struct kvm_coalesced_mmio' object, wherein write indices 'ring->first' and 'ring->last' value could be
    supplied by a host user-space process. An unprivileged host user or process with access to '/dev/kvm'
    device could use this flaw to crash the host kernel, resulting in a denial of service or potentially
    escalating privileges on the system. (CVE-2019-14821)

  - A buffer overflow flaw was found, in versions from 2.6.34 to 5.2.x, in the way Linux kernel's vhost
    functionality that translates virtqueue buffers to IOVs, logged the buffer descriptors during migration. A
    privileged guest user able to pass descriptors with invalid length to the host when migration is underway,
    could use this flaw to increase their privileges on the host. (CVE-2019-14835)

  - A heap-based buffer overflow was discovered in the Linux kernel, all versions 3.x.x and 4.x.x before
    4.18.0, in Marvell WiFi chip driver. The flaw could occur when the station attempts a connection
    negotiation during the handling of the remote devices country settings. This could allow the remote device
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2019-14895)

  - The fix for CVE-2019-11599, affecting the Linux kernel before 5.0.10 was not complete. A local user could
    use this flaw to obtain sensitive information, cause a denial of service, or possibly have other
    unspecified impacts by triggering a race condition with mmget_not_zero or get_task_mm calls.
    (CVE-2019-14898)

  - A heap overflow flaw was found in the Linux kernel, all versions 3.x.x and 4.x.x before 4.18.0, in Marvell
    WiFi chip driver. The vulnerability allows a remote attacker to cause a system crash, resulting in a
    denial of service, or execute arbitrary code. The highest threat with this vulnerability is with the
    availability of the system. If code execution occurs, the code will run with the permissions of root. This
    will affect both confidentiality and integrity of files on the system. (CVE-2019-14901)

  - In the Linux kernel, a certain net/ipv4/tcp_output.c change, which was properly incorporated into 4.16.12,
    was incorrectly backported to the earlier longterm kernels, introducing a new vulnerability that was
    potentially more severe than the issue that was intended to be fixed by backporting. Specifically, by
    adding to a write queue between disconnection and re-connection, a local attacker can trigger multiple
    use-after-free conditions. This can result in a kernel crash, or potentially in privilege escalation.
    NOTE: this affects (for example) Linux distributions that use 4.9.x longterm kernels before 4.9.190 or
    4.14.x longterm kernels before 4.14.139. (CVE-2019-15239)

  - In the Linux kernel through 5.3.2, cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c does not reject a
    long SSID IE, leading to a Buffer Overflow. (CVE-2019-17133)

  - A buffer overflow in the fribidi_get_par_embedding_levels_ex() function in lib/fribidi-bidi.c of GNU
    FriBidi through 1.0.7 allows an attacker to cause a denial of service or possibly execute arbitrary code
    by delivering crafted text content to a user, when this content is then rendered by an application that
    uses FriBidi for text layout calculations. Examples include any GNOME or GTK+ based application that uses
    Pango for text layout, as this internally uses FriBidi for bidirectional text layout. For example, the
    attacker can construct a crafted text file to be opened in GEdit, or a crafted IRC message to be viewed in
    HexChat. (CVE-2019-18397)

  - In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer
    overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS;
    however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an
    administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.
    (CVE-2019-18634)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking).
    Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to
    Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2019-2945)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Kerberos). Supported
    versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via Kerberos to compromise Java
    SE, Java SE Embedded. While the vulnerability is in Java SE, Java SE Embedded, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2949)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: 2D). Supported
    versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2962)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Concurrency).
    Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component
    without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web
    service. (CVE-2019-2964)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: JAXP). Supported
    versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2973, CVE-2019-2981)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Scripting). Supported
    versions that are affected are Java SE: 8u221, 11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Java SE, Java SE Embedded accessible data and unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2975)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking).
    Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2978)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Serialization).
    Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2983)

  - Vulnerability in the Java SE product of Oracle Java SE (component: 2D). Supported versions that are
    affected are Java SE: 11.0.4 and 13. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a partial denial of service (partial DOS) of Java SE. Note:
    This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2987)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: 2D). Supported
    versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to
    Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2019-2988, CVE-2019-2992)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking).
    Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. While the vulnerability is in Java SE, Java SE
    Embedded, attacks may significantly impact additional products. Successful attacks of this vulnerability
    can result in unauthorized creation, deletion or modification access to critical data or all Java SE, Java
    SE Embedded accessible data. Note: This vulnerability applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service
    which supplies data to the APIs. (CVE-2019-2989)

  - Vulnerability in the Java SE product of Oracle Java SE (component: Javadoc). Supported versions that are
    affected are Java SE: 7u231, 8u221, 11.0.4 and 13. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Java SE. Successful
    attacks require human interaction from a person other than the attacker and while the vulnerability is in
    Java SE, attacks may significantly impact additional products. Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete access to some of Java SE accessible data as well as
    unauthorized read access to a subset of Java SE accessible data. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets
    (in Java SE 8), that load and run untrusted code (e.g., code that comes from the internet) and rely on the
    Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers,
    that load and run only trusted code (e.g., code installed by an administrator). (CVE-2019-2999)

  - A heap address information leak while using L2CAP_GET_CONF_OPT was discovered in the Linux kernel before
    5.1-rc1. (CVE-2019-3459)

  - A heap data infoleak in multiple locations including L2CAP_PARSE_CONF_RSP was found in the Linux kernel
    before 5.1-rc1. (CVE-2019-3460)

  - A flaw that allowed an attacker to corrupt memory and possibly escalate privileges was found in the
    mwifiex kernel module while connecting to a malicious wireless network. (CVE-2019-3846)

  - A flaw was found in the Linux kernel's vfio interface implementation that permits violation of the user's
    locked memory limit. If a device is bound to a vfio driver, such as vfio-pci, and the local attacker is
    administratively granted ownership of the device, it may cause a system memory exhaustion and thus a
    denial of service (DoS). Versions 3.10, 4.14 and 4.18 are vulnerable. (CVE-2019-3882)

  - An infinite loop issue was found in the vhost_net kernel module in Linux Kernel up to and including
    v5.1-rc6, while handling incoming packets in handle_rx(). It could occur if one end sends packets faster
    than the other end can process them. A guest user, maybe remote one, could use this flaw to stall the
    vhost_net kernel thread, resulting in a DoS scenario. (CVE-2019-3900)

  - The mincore() implementation in mm/mincore.c in the Linux kernel through 4.19.13 allowed local attackers
    to observe page cache access patterns of other processes on the same system, potentially allowing sniffing
    of secret information. (Fixing this affects the output of the fincore program.) Limited remote
    exploitation may be possible, as demonstrated by latency differences in accessing public files from an
    Apache HTTP Server. (CVE-2019-5489)

  - OpenSLP as used in ESXi and the Horizon DaaS appliances has a heap overwrite issue. VMware has evaluated
    the severity of this issue to be in the Critical severity range with a maximum CVSSv3 base score of 9.8.
    (CVE-2019-5544)

  - The KVM implementation in the Linux kernel through 4.20.5 has an Information Leak. (CVE-2019-7222)

  - The Broadcom brcmfmac WiFi driver prior to commit 1b5e2423164b3670e8bc9174e4762d297990deff is vulnerable
    to a heap buffer overflow. If the Wake-up on Wireless LAN functionality is configured, a malicious event
    frame can be constructed to trigger an heap buffer overflow in the brcmf_wowl_nd_results function. This
    vulnerability can be exploited with compromised chipsets to compromise the host, or when used in
    combination with CVE-2019-9503, can be used remotely. In the worst case scenario, by sending specially-
    crafted WiFi packets, a remote, unauthenticated attacker may be able to execute arbitrary code on a
    vulnerable system. More typically, this vulnerability will result in denial-of-service conditions.
    (CVE-2019-9500)

  - The Bluetooth BR/EDR specification up to and including version 5.1 permits sufficiently low encryption key
    length and does not prevent an attacker from influencing the key length negotiation. This allows practical
    brute-force attacks (aka KNOB) that can decrypt traffic and inject arbitrary ciphertext without the
    victim noticing. (CVE-2019-9506)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Serialization).
    Supported versions that are affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1; Java SE Embedded:
    8u231. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2020-2583)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Security). Supported
    versions that are affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1; Java SE Embedded: 8u231.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via Kerberos to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2020-2590)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking).
    Supported versions that are affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1; Java SE Embedded:
    8u231. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Java SE, Java SE Embedded accessible data as well
    as unauthorized read access to a subset of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2020-2593)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Security). Supported
    versions that are affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1; Java SE Embedded: 8u231.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via Kerberos to
    compromise Java SE, Java SE Embedded. While the vulnerability is in Java SE, Java SE Embedded, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access to all Java SE, Java SE Embedded accessible data.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2020-2601)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Serialization).
    Supported versions that are affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1; Java SE Embedded:
    8u231. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    takeover of Java SE, Java SE Embedded. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets (in Java SE 8), that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through
    a web service which supplies data to the APIs. (CVE-2020-2604)

  - Vulnerability in the Java SE product of Oracle Java SE (component: Libraries). Supported versions that are
    affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Java SE. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service
    (partial DOS) of Java SE. Note: This vulnerability can only be exploited by supplying data to APIs in the
    specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as
    through a web service. (CVE-2020-2654)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking).
    Supported versions that are affected are Java SE: 7u241 and 8u231; Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2020-2659)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.11.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4db5786a");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14901");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5544");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.11.3', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.11.3 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '5.11.3', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.11.3 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);
