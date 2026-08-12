/* ksu-load.c — KernelSU manual-relocation loader for Samsung 5.10 (zero-__versions ko).
 *
 * Method (BuSung late_load style): the module was built with a zero-length
 * __versions section (no modversions CRC) but keeps a full .symtab of
 * UNDEFINED symbols.  CONFIG_TRIM_UNUSED_KSYMS stripped most of them from the
 * kernel's export table, so a plain insmod would fail to resolve them.
 * Before init_module(2), every UNDEF symbol is rewritten in-place to
 * SHN_ABS with st_value = absolute address looked up from /proc/kallsyms.
 * The kernel module loader then applies the RELA relocations against those
 * absolute values exactly as if the symbols were defined in the module.
 *
 * Usage: ksu-load <module.ko> [param=value ...]
 * Build: $ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/\
 *        aarch64-linux-android30-clang -static -O2 -o ksu-load ksu-load.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifndef __NR_init_module
#define __NR_init_module 105
#endif

/* ELF64 bits we need */
#define EI_NIDENT 16
#define EI_CLASS 4
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define ET_REL 1
#define EM_AARCH64 183
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_PROGBITS 1
#define SHN_UNDEF 0
#define SHN_ABS 0xfff1
#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STB_GLOBAL 1
#define STB_WEAK 2
#define STB_GNU_UNIQUE 10

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t Elf64_Sxword;

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off e_phoff;
    Elf64_Off e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf64_Word sh_name;
    Elf64_Word sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr sh_addr;
    Elf64_Off sh_offset;
    Elf64_Xword sh_size;
    Elf64_Word sh_link;
    Elf64_Word sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;
} Elf64_Shdr;

typedef struct {
    Elf64_Word st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Half st_shndx;
    Elf64_Addr st_value;
    Elf64_Xword st_size;
} Elf64_Sym;

/* ---- /proc/kallsyms lookup (root: full table visible) ---- */
#define KSYM_MAX 600000
static char *ksym_names[KSYM_MAX];
static unsigned long long ksym_addrs[KSYM_MAX];
static int ksym_count;

static int load_kallsyms(void)
{
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        fprintf(stderr, "kallsyms open failed: %s\n", strerror(errno));
        return -1;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp) && ksym_count < KSYM_MAX) {
        char type;
        unsigned long long addr;
        char name[256];
        if (sscanf(line, "%llx %c %255s", &addr, &type, name) == 3 &&
            addr != 0) {   /* kptr_restrict hides addresses as 0: skip */
            ksym_addrs[ksym_count] = addr;
            ksym_names[ksym_count] = strdup(name);
            ksym_count++;
        }
    }
    fclose(fp);
    fprintf(stderr, "kallsyms: %d entries (addr!=0)\n", ksym_count);
    return ksym_count > 0 ? 0 : -1;
}

static int ksym_lookup(const char *name, unsigned long long *addr)
{
    for (int i = 0; i < ksym_count; i++) {
        if (strcmp(ksym_names[i], name) == 0) {
            *addr = ksym_addrs[i];
            return 0;
        }
    }
    return -1;
}

static char *join_params(int argc, char **argv, int start)
{
    size_t len = 1;
    for (int i = start; i < argc; i++)
        len += strlen(argv[i]) + 1;
    char *buf = calloc(1, len);
    if (!buf)
        return NULL;
    for (int i = start; i < argc; i++) {
        if (i > start)
            strcat(buf, " ");
        strcat(buf, argv[i]);
    }
    return buf;
}

static int ksu_load_file(const char *ko_path, const char *params)
{
    int fd = open(ko_path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", ko_path, strerror(errno)); return 1; }
    struct stat st;
    if (fstat(fd, &st) != 0) { perror("fstat"); return 1; }
    unsigned char *buf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE, fd, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }

    /* Optional vermagic patch: the official KSU ko carries
     * 5.10.252-dirty but the device needs its exact VERMAGIC_STRING.
     * We shorten unused modinfo fields to make room, then rewrite the
     * vermagic value (it is the last field in .modinfo). */
    if (getenv("KSU_VERMAGIC_PATCH")) {
        char *modinfo = NULL;
        size_t mi_size = 0;
        Elf64_Ehdr *eh0 = (Elf64_Ehdr *)buf;
        Elf64_Shdr *sh0 = (Elf64_Shdr *)(buf + eh0->e_shoff);
        for (int i = 0; i < eh0->e_shnum; i++) {
            if (sh0[i].sh_type == SHT_PROGBITS && sh0[i].sh_size > 100) {
                /* .modinfo is the section whose content starts with
                 * "parmtype=" or contains "vermagic=" */
                const char *p = (const char *)(buf + sh0[i].sh_offset);
                size_t sz = sh0[i].sh_size;
                if (memmem(p, sz, "vermagic=", 9)) {
                    modinfo = (char *)p;
                    mi_size = sz;
                    break;
                }
            }
        }
        if (modinfo) {
            /* 1) shorten scmversion/author/description to free bytes */
            struct { const char *old; const char *neu; } subs[] = {
                { "scmversion=gb0bc817b4e96", "scmversion=x" },
                { "author=weishu",            "author=w" },
                { "description=Android KernelSU", "description=KSU" },
            };
            for (size_t i = 0; i < sizeof(subs)/sizeof(subs[0]); i++) {
                char *f = strstr(modinfo, subs[i].old);
                if (f) {
                    size_t olen = strlen(subs[i].old);
                    size_t nlen = strlen(subs[i].neu);
                    memcpy(f, subs[i].neu, nlen);
                    memset(f + nlen, 0, olen - nlen);
                }
            }
            /* 2) rewrite vermagic (last field): slide the whole tail left
             * by the freed bytes, then write the device string. */
            const char *dev_vermagic =
                "5.10.236-android12-9-2755199-abF9360ZCSAIZF1 "
                "SMP preempt mod_unload modversions aarch64";
            char *vp = strstr(modinfo, "vermagic=");
            if (vp) {
                /* freed = sum of (olen - nlen) */
                size_t freed =
                    (strlen("scmversion=gb0bc817b4e96") - strlen("scmversion=x")) +
                    (strlen("author=weishu") - strlen("author=w")) +
                    (strlen("description=Android KernelSU") - strlen("description=KSU"));
                size_t tail = mi_size - (size_t)(vp - modinfo);
                memmove(vp - freed, vp, tail);
                vp -= freed;
                size_t room = tail + freed - strlen("vermagic=");
                if (room >= strlen(dev_vermagic) + 1) {
                    memcpy(vp, "vermagic=", 9);
                    memcpy(vp + 9, dev_vermagic, strlen(dev_vermagic) + 1);
                    fprintf(stderr, "vermagic patched -> %s\n", dev_vermagic);
                } else {
                    fprintf(stderr, "vermagic patch failed: room=%zu need=%zu\n",
                            room, strlen(dev_vermagic) + 1);
                }
            }
        } else {
            fprintf(stderr, "vermagic patch: .modinfo not found\n");
        }
    }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    if (memcmp(eh->e_ident, "\x7f" "ELF", 4) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_machine != EM_AARCH64) {
        fprintf(stderr, "not an aarch64 ELF\n");
        return 1;
    }
    Elf64_Shdr *sh = (Elf64_Shdr *)(buf + eh->e_shoff);
    const char *shstr = (const char *)(buf + sh[eh->e_shstrndx].sh_offset);

    if (load_kallsyms() != 0)
        return 1;

    /* find .symtab and .strtab */
    Elf64_Shdr *symtab = NULL, *strtab = NULL;
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type == SHT_SYMTAB) symtab = &sh[i];
        if (sh[i].sh_type == SHT_STRTAB && strtab == NULL && i != eh->e_shstrndx)
            strtab = &sh[i];
    }
    if (!symtab || !strtab) {
        fprintf(stderr, "no symtab/strtab\n");
        return 1;
    }
    const char *strs = (const char *)(buf + strtab->sh_offset);
    Elf64_Sym *syms = (Elf64_Sym *)(buf + symtab->sh_offset);
    int nsyms = symtab->sh_size / sizeof(Elf64_Sym);

    int patched = 0, missing = 0, skipped = 0;
    for (int i = 0; i < nsyms; i++) {
        Elf64_Sym *s = &syms[i];
        if (s->st_shndx != SHN_UNDEF)
            continue;
        int bind = s->st_info >> 4;
        if (bind != STB_GLOBAL && bind != STB_WEAK) {
            skipped++;
            continue;
        }
        const char *name = strs + s->st_name;
        if (!name[0] || !strcmp(name, "_GLOBAL_OFFSET_TABLE_")) {
            skipped++;
            continue;
        }
        unsigned long long addr = 0;
        if (ksym_lookup(name, &addr) != 0 || addr == 0) {
            fprintf(stderr, "MISSING symbol: %s\n", name);
            missing++;
            continue;
        }
        s->st_shndx = SHN_ABS;
        s->st_value = addr;
        patched++;
    }
    fprintf(stderr, "symbols patched=%d missing=%d skipped=%d\n",
            patched, missing, skipped);
    if (missing) {
        fprintf(stderr, "aborting: %d symbols unresolvable\n", missing);
        return 1;
    }

    fprintf(stderr, "init_module(%s)...\n", ko_path);
    long ret = syscall(__NR_init_module, buf, st.st_size, params);
    if (ret != 0) {
        fprintf(stderr, "init_module failed: %s (errno=%d)\n",
                strerror(errno), errno);
        return 1;
    }
    printf("KernelSU loaded OK (manual relocation, %d symbols)\n", patched);
    return 0;
}

#ifdef KSU_LOAD_AS_SO
/* LD_PRELOAD variant: DEFEX blocks execve() of new /data/local/tmp
 * binaries, but library loading via the dynamic linker is not hooked.
 * Constructor runs in the host process (any pre-existing binary) with
 * full root privileges. */

/* exec env without LD_PRELOAD (would poison the child's linker) */
static char **clean_envp(void)
{
    extern char **environ;
    static char *buf[64];
    int n = 0;
    for (int i = 0; environ[i] && n < 62; i++) {
        if (strncmp(environ[i], "LD_PRELOAD=", 11) == 0 ||
            strncmp(environ[i], "LD_LIBRARY_PATH=", 16) == 0 ||
            strncmp(environ[i], "KSU_", 4) == 0)
            continue;
        buf[n++] = environ[i];
    }
    buf[n] = NULL;
    return buf;
}

static void ksu_exec_ksud(void)
{
    const char *ksud = getenv("KSU_KSUD_PATH");
    if (!ksud) ksud = "/data/local/tmp/ksud-samsung-android12-5.10-kdp";
    const char *args_env = getenv("KSU_KSUD_ARGS");
    if (!args_env) args_env = "late-load --allow-shell";

    /* Drop domain kernel:s0 -> shell:s0 so DEFEX allows the execve.
     * The new domain applies at the next exec (setexeccon). */
    int fd = open("/proc/self/attr/exec", O_WRONLY);
    if (fd >= 0) {
        if (write(fd, "u:r:shell:s0", 12) != 12)
            fprintf(stderr, "setexeccon write failed errno=%d\n", errno);
        close(fd);
    } else {
        fprintf(stderr, "open attr/exec failed errno=%d\n", errno);
    }

    char *argv[16];
    int argc = 0;
    argv[argc++] = (char *)ksud;
    char *copy = strdup(args_env);
    char *tok = strtok(copy, " ");
    while (tok && argc < 14) {
        argv[argc++] = tok;
        tok = strtok(NULL, " ");
    }
    argv[argc] = NULL;

    /* redirect child output to a log */
    int lfd = open("/data/local/tmp/ksud-exec.log",
                   O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (lfd >= 0) {
        dup2(lfd, STDOUT_FILENO);
        dup2(lfd, STDERR_FILENO);
        close(lfd);
    }

    pid_t pid = fork();
    if (pid == 0) {
        execve(ksud, argv, clean_envp());
        fprintf(stderr, "execve failed errno=%d\n", errno);
        _exit(127);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
    }
    fprintf(stderr, "ksud child exit status=%d\n", st);
    _exit(0);
}

__attribute__((constructor)) static void ksu_load_entry(void)
{
    /* unbuffered output: crash inside init_module must leave a trace */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    const char *mode = getenv("KSU_EXEC_MODE");
    if (mode && strcmp(mode, "ksud") == 0) {
        ksu_exec_ksud();
        return;
    }
    if (mode && strcmp(mode, "probe") == 0) {
        int lfd = open("/data/local/tmp/probe.log",
                       O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (lfd >= 0) {
            dup2(lfd, STDOUT_FILENO);
            dup2(lfd, STDERR_FILENO);
            close(lfd);
        }
        fprintf(stderr, "probe pid=%d cur=", getpid());
        {
            int f = open("/proc/self/attr/current", O_RDONLY);
            if (f >= 0) {
                char c[64] = {0};
                read(f, c, sizeof(c) - 1);
                fprintf(stderr, "%s", c);
                close(f);
            }
        }
        fprintf(stderr, "\n");

        const char *pm = getenv("KSU_PROBE_METHOD");
        if (pm && strcmp(pm, "setcon") == 0) {
            /* setcon directly (attr/current) */
            int f = open("/proc/self/attr/current", O_WRONLY);
            if (f >= 0) {
                ssize_t w = write(f, "u:r:shell:s0", 12);
                fprintf(stderr, "setcon write=%zd errno=%d\n", w, errno);
                close(f);
            }
        } else {
            int f = open("/proc/self/attr/exec", O_WRONLY);
            if (f >= 0) {
                ssize_t w = write(f, "u:r:shell:s0", 12);
                fprintf(stderr, "setexeccon write=%zd errno=%d\n", w, errno);
                close(f);
            }
        }

        pid_t pid = fork();
        fprintf(stderr, "forked=%d\n", pid);
        if (pid == 0) {
            fprintf(stderr, "child pre-exec cur=");
            {
                int f = open("/proc/self/attr/current", O_RDONLY);
                if (f >= 0) {
                    char c[64] = {0};
                    read(f, c, sizeof(c) - 1);
                    fprintf(stderr, "%s", c);
                    close(f);
                }
            }
            fprintf(stderr, "\n");
            execl("/system/bin/sh", "sh", "-c",
                  "echo SH-ALIVE; cat /proc/self/attr/current; id",
                  (char *)NULL);
            fprintf(stderr, "execve failed errno=%d\n", errno);
            _exit(127);
        }
        int st = 0;
        waitpid(pid, &st, 0);
        fprintf(stderr, "child exit status=%d\n", st);
        _exit(0);
    }
    const char *ko = getenv("KSU_KO_PATH");
    const char *params = getenv("KSU_KO_PARAMS");
    if (!ko) ko = "/data/local/tmp/kernelsu-kdp.ko";
    if (!params) params = "allow_shell=1";
    ksu_load_file(ko, params);
}
#else
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <module.ko> [param=value ...]\n", argv[0]);
        return 2;
    }
    char *params = join_params(argc, argv, 2);
    if (!params) { fprintf(stderr, "oom\n"); return 1; }
    int rc = ksu_load_file(argv[1], params);
    return rc;
}
#endif
