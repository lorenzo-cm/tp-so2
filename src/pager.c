#include "pager.h"

#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "mmu.h"

struct frame_data {
	pid_t pid;
	int page;
	int prot; /* PROT_READ (clean) or PROT_READ | PROT_WRITE (dirty) */
	int dirty; /* prot may be reset by pager_free_frame() */
};

struct page_data {
	int block;
	int on_disk; /* 0 indicates page was written to disk */
	int frame; /* -1 indicates non-resident */
};

struct proc {
	pid_t pid;
	int npages;
	int maxpages;
	struct page_data *pages;
};

struct pager {
	pthread_mutex_t mutex;
	int nframes;
	int frames_free;
	int clock;
	struct frame_data *frames;
	int nblocks;
	int blocks_free;
	pid_t *block2pid;
	struct proc **pid2proc;
};

struct pager pager;

void pager_init(int nframes, int nblocks) {
    pthread_mutex_init(&pager.mutex, NULL);

    pager.nframes = nframes;
    pager.frames_free = nframes;
    pager.clock = 0;
    pager.frames = (struct frame_data *) malloc(nframes * sizeof(struct frame_data));
    for (int i = 0; i < nframes; i++) {
        pager.frames[i].pid = -1;
        pager.frames[i].page = -1;
        pager.frames[i].prot = 0;
        pager.frames[i].dirty = 0;
    }


    pager.nblocks = nblocks;
    pager.blocks_free = nblocks;
    pager.block2pid = (pid_t *) malloc(nblocks * sizeof(pid_t));
    for (int i = 0; i < nblocks; i++) {
        pager.block2pid[i] = -1;
    }

    pager.pid2proc = NULL; // Inicialmente nenhum processo conectado
}

void pager_create(pid_t pid) {
    pthread_mutex_lock(&pager.mutex);

    struct proc *new_proc = (struct proc *) malloc(sizeof(struct proc));
    new_proc->pid = pid;
    new_proc->npages = 0;
    new_proc->maxpages = 10; // Valor inicial, pode ser ajustado conforme necessário
    new_proc->pages = (struct page_data *) malloc(new_proc->maxpages * sizeof(struct page_data));
    for (int i = 0; i < new_proc->maxpages; i++) {
        new_proc->pages[i].block = -1;
        new_proc->pages[i].on_disk = 0;
        new_proc->pages[i].frame = -1;
    }

    // Adicionar o novo processo à lista de processos
    // Encontrar um espaço vazio ou expandir a lista
    int found = 0;
    for (int i = 0; i < pager.nframes; i++) {
        if (pager.pid2proc == NULL) {
            pager.pid2proc = (struct proc **) malloc(pager.nframes * sizeof(struct proc *));
            for (int j = 0; j < pager.nframes; j++) {
                pager.pid2proc[j] = NULL;
            }
        }

        if (pager.pid2proc[i] == NULL) {
            pager.pid2proc[i] = new_proc;
            found = 1;
            break;
        }
    }

    if (!found) {
        // Expandir a lista de processos se necessário
        pager.pid2proc = (struct proc **) realloc(pager.pid2proc, (pager.nframes + 1) * sizeof(struct proc *));
        pager.pid2proc[pager.nframes] = new_proc;
    }

    pthread_mutex_unlock(&pager.mutex);
}


void pager_destroy(pid_t pid) {
    pthread_mutex_lock(&pager.mutex);

    for (int i = 0; i < pager.nframes; i++) {
        if (pager.pid2proc[i] != NULL && pager.pid2proc[i]->pid == pid) {
            // Liberar as páginas do processo
            free(pager.pid2proc[i]->pages);
            // Liberar a estrutura do processo
            free(pager.pid2proc[i]);
            // Remover o processo da lista de processos
            pager.pid2proc[i] = NULL;
            break;
        }
    }

    pthread_mutex_unlock(&pager.mutex);
}


void* pager_extend(pid_t pid) {
    pthread_mutex_lock(&pager.mutex);

    // Encontrar o processo correspondente
    struct proc *process = NULL;
    for (int i = 0; i < pager.nframes; i++) {
        if (pager.pid2proc[i] && pager.pid2proc[i]->pid == pid) {
            process = pager.pid2proc[i];
            break;
        }
    }

    if (process == NULL) {
        pthread_mutex_unlock(&pager.mutex);
        return NULL; // Processo não encontrado
    }

    // Verificar se há espaço para alocar uma nova página
    if (process->npages >= process->maxpages) {
        // Reallocar o array de páginas se necessário
        int new_maxpages = process->maxpages * 2;
        struct page_data *new_pages = (struct page_data *) realloc(process->pages, new_maxpages * sizeof(struct page_data));
        if (!new_pages) {
            pthread_mutex_unlock(&pager.mutex);
            return NULL; // Falha na realocação de memória
        }
        process->pages = new_pages;
        process->maxpages = new_maxpages;
    }

    // Encontrar um bloco de disco livre
    int block = -1;
    for (int i = 0; i < pager.nblocks; i++) {
        if (pager.block2pid[i] == -1) { // Bloco está livre
            block = i;
            pager.block2pid[i] = pid;
            pager.blocks_free--;
            break;
        }
    }

    if (block == -1) {
        pthread_mutex_unlock(&pager.mutex);
        return NULL; // Sem blocos de disco disponíveis
    }

    // Configurar a nova página no processo
    int page_idx = process->npages;
    process->pages[page_idx].block = block;
    process->pages[page_idx].on_disk = 1; // Página está no disco
    process->pages[page_idx].frame = -1;  // Página não está residente na memória
    process->npages++;

    // Calcular o endereço virtual da nova página usando UVM_BASEADDR
    void* addr_ptr = (void*)(UVM_BASEADDR + (uintptr_t)(page_idx * 4096));

    pthread_mutex_unlock(&pager.mutex);
    return addr_ptr; // Retorna o endereço virtual da nova página
}


void pager_fault(pid_t pid, void* vaddr) {
    pthread_mutex_lock(&pager.mutex);

    // Encontrar o processo correspondente
    struct proc *process = NULL;
    for (int i = 0; i < pager.nframes; i++) {
        if (pager.pid2proc[i] && pager.pid2proc[i]->pid == pid) {
            process = pager.pid2proc[i];
            break;
        }
    }

    if (process == NULL) {
        pthread_mutex_unlock(&pager.mutex);
        fprintf(stderr, "Processo não encontrado!\n");
        return;
    }

    // Calcular o índice da página
    int page_idx = ((unsigned long)vaddr - UVM_BASEADDR) / 4096;

    if (page_idx < 0 || page_idx >= process->npages) {
        pthread_mutex_unlock(&pager.mutex);
        fprintf(stderr, "Endereço virtual inválido!\n");
        return;
    }

    struct page_data *page = &process->pages[page_idx];

    // Verificar se a página já está residente
    if (page->frame != -1) {
        pthread_mutex_unlock(&pager.mutex);

        // Modificar as permissões para leitura e escrita na segunda falha de página
        mmu_chprot(pid, vaddr, PROT_READ | PROT_WRITE);
        printf("mmu_chprot pid %d vaddr %p prot %d\n", pid, vaddr, PROT_READ | PROT_WRITE);
        return;
    }

    // Obter um quadro de memória física
    int frame_idx = -1;
    if (pager.frames_free > 0) {
        // Encontre o primeiro quadro livre
        for (int i = 0; i < pager.nframes; i++) {
            if (pager.frames[i].pid == -1) {
                frame_idx = i;
                pager.frames_free--;
                break;
            }
        }
    } else {
        // Algoritmo de segunda chance
        while (1) {
            frame_idx = pager.clock;
            pager.clock = (pager.clock + 1) % pager.nframes;

            if (pager.frames[frame_idx].prot & PROT_READ) {
                // Dar uma segunda chance: desmarcar o bit de leitura
                pager.frames[frame_idx].prot &= ~PROT_READ;
            } else {
                // Este quadro será liberado
                if (pager.frames[frame_idx].dirty) {
                    // Escrever de volta no disco se estiver sujo
                    int block_to = process->pages[pager.frames[frame_idx].page].block;
                    mmu_disk_write(frame_idx, block_to);
                }
                break;
            }
        }

        // Desmarcar a página antiga no processo correspondente
        struct proc *old_proc = NULL;
        for (int i = 0; i < pager.nframes; i++) {
            if (pager.pid2proc[i] && pager.pid2proc[i]->pid == pager.frames[frame_idx].pid) {
                old_proc = pager.pid2proc[i];
                break;
            }
        }

        if (old_proc) {
            old_proc->pages[pager.frames[frame_idx].page].frame = -1;
            old_proc->pages[pager.frames[frame_idx].page].on_disk = 1; // Marca como estando no disco
        }
    }

    // Preencher o quadro com zeros e mapear o endereço virtual
    mmu_zero_fill(frame_idx);
    mmu_resident(pid, vaddr, frame_idx, PROT_READ);

    // Atualizar a página e o quadro
    page->frame = frame_idx;
    page->on_disk = 0;
    pager.frames[frame_idx].pid = pid;
    pager.frames[frame_idx].page = page_idx;
    pager.frames[frame_idx].prot = PROT_READ;
    pager.frames[frame_idx].dirty = 0;

    pthread_mutex_unlock(&pager.mutex);
}


int pager_syslog(pid_t pid, void *addr, size_t len) {
    pthread_mutex_lock(&pager.mutex);

    // Encontrar o processo correspondente
    struct proc *process = NULL;
    for (int i = 0; i < pager.nframes; i++) {
        if (pager.pid2proc[i] && pager.pid2proc[i]->pid == pid) {
            process = pager.pid2proc[i];
            break;
        }
    }

    if (process == NULL) {
        pthread_mutex_unlock(&pager.mutex);
        errno = EINVAL;
        return -1; // Processo não encontrado
    }

    // Calcular o índice da primeira página
    int page_idx = ((unsigned long)addr - UVM_BASEADDR) / 4096;
    if (page_idx < 0 || page_idx >= process->npages) {
        pthread_mutex_unlock(&pager.mutex);
        errno = EINVAL;
        return -1; // Endereço virtual fora do espaço alocado
    }

    // Verificar se todos os bytes estão em páginas alocadas
    int last_page_idx = ((unsigned long)addr + len - 1 - UVM_BASEADDR) / 4096;
    if (last_page_idx < 0 || last_page_idx >= process->npages) {
        pthread_mutex_unlock(&pager.mutex);
        errno = EINVAL;
        return -1; // Tentativa de acesso fora do espaço alocado
    }

    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) {
        pthread_mutex_unlock(&pager.mutex);
        errno = ENOMEM;
        return -1; // Falha na alocação de memória
    }

    // Copiar os dados das páginas de memória (resolvendo falhas de página, se necessário)
    for (size_t i = 0; i < len; i++) {
        void *current_addr = (void *)((unsigned long)addr + i);
        int current_page_idx = ((unsigned long)current_addr - UVM_BASEADDR) / 4096;
        struct page_data *page = &process->pages[current_page_idx];

        // Resolver falha de página se necessário
        if (page->frame == -1) {
            // Página não está residente, gerar uma falha de página
            pager_fault(pid, (void *)((unsigned long)current_addr & ~0xFFF)); // Endereço alinhado à página
        }

        // Calcular o endereço físico
        unsigned long offset = (unsigned long)current_addr & 0xFFF;
        const char *physical_addr = pmem + page->frame * 4096 + offset;

        // Copiar o byte para o buffer
        buf[i] = *physical_addr;
    }

    pthread_mutex_unlock(&pager.mutex);

    // Imprimir os bytes em formato hexadecimal
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    free(buf);
    return 0; // Sucesso
}