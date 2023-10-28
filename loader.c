#include "loader.h"

Elf32_Ehdr *ehdr;
int fd;
int page_size;
int total_page_faults = 0;
int total_page_allocations = 0;
int total_internal_fragmentation = 0;
jmp_buf env;

int read_file(char *exe) {
    int file_fd = open(exe, O_RDONLY);
    if (file_fd == -1) {
        printf("Error opening file");
        exit(1);
    }
    return file_fd;
}

void loader_cleanup() {
    if (ehdr != NULL) {
        free(ehdr);
        ehdr = NULL;
    }
    if (phdr != NULL) {
        free(phdr);
        phdr = NULL;
    }
}

// Signal handler for handling page faults
void page_fault_handler(int signum, siginfo_t *info, void *context) {
    void *fault_addr = info->si_addr;
    void *page_start = (void*)((unsigned long)fault_addr & ~(page_size - 1));
    void *alloc_memory = mmap(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, 0, 0);

    if (alloc_memory == MAP_FAILED) {
        perror("mmap failed");
        exit(1);
    }

    total_page_allocations++;
    total_internal_fragmentation += page_size / 1024;
    
    printf("Page allocation at address: %p\n", alloc_memory);

    // Resume execution after page allocation
    siglongjmp(env, 1);
}

void load_and_run_elf(char *exe) {
    fd = read_file(exe);

    ehdr = malloc(sizeof(Elf32_Ehdr));
    if (read(fd, ehdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
        perror("Error reading ELF header");
        close(fd);
        exit(1);
    }

    // Calculate the page size for mmap
    page_size = sysconf(_SC_PAGE_SIZE);

    // Set up a signal handler for page faults
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_sigaction = page_fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    // Execute the ELF binary using sigsetjmp/siglongjmp to handle page faults
    if (sigsetjmp(env, 1) == 0) {
        Elf32_Addr entrypoint = ehdr->e_entry;
        int (*entry_func)() = (int (*)())entrypoint;
        int result = entry_func();
        printf("User _start return value = %d\n", result);
    }

    // Clean up and report statistics
    close(fd);
    loader_cleanup();
    printf("Total page faults: %d\n", total_page_faults);
    printf("Total page allocations: %d\n", total_page_allocations);
    printf("Total internal fragmentation: %d KB\n", total_internal_fragmentation);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <ELF Executable>\n", argv[0]);
        exit(1);
    }

    load_and_run_elf(argv[1]);

    return 0;
}
