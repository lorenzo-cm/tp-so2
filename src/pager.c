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

    // Setar novo processo
    struct proc *new_proc = (struct proc *) malloc(sizeof(struct proc));

    new_proc->pid = pid;
    new_proc->npages = 0;
    new_proc->maxpages = (UVM_MAXADDR - UVM_BASEADDR + 1) / sysconf(_SC_PAGESIZE);
    new_proc->pages = (struct page_data *) malloc(new_proc->maxpages * sizeof(struct page_data));

    for (int i = 0; i < new_proc->maxpages; i++) {
        new_proc->pages[i].block = -1;      // -1 para indicar que ainda não foi alocado
        new_proc->pages[i].on_disk = 0;
        new_proc->pages[i].frame = -1;      // -1 para indicar que ainda não foi alocado
    }

    

    // Se pid2proc ainda não foi inicializado, então é inicializado
    if (pager.pid2proc == NULL) {
        pager.pid2proc = (struct proc **) malloc(pager.nframes * sizeof(struct proc *));
        for (int i = 0; i < pager.nframes; i++) {
            pager.pid2proc[i] = NULL;
        }
    }

    // Adicionar o novo processo à lista de processos
    // Para isso é necessário procurar por um lugar vago
    int found = 0;
    for (int i = 0; i < pager.nframes; i++) {
        // Se o lugar estiver vago
        if (pager.pid2proc[i] == NULL) {
            pager.pid2proc[i] = new_proc;
            found = 1;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "Não foi possível alocar novo processo\n");
    }

    pthread_mutex_unlock(&pager.mutex);
}


void pager_destroy(pid_t pid) {
    pthread_mutex_lock(&pager.mutex);

    // Procurar processo PID
    struct proc *proc = NULL;
    for (int i=0; i<pager.nblocks; i++) {
        if (pager.pid2proc[i]->pid == pid) {
            proc = pager.pid2proc[i];
            break;
        }
    }

    // Resetar/limpar processo
    proc->pid = -1;
    proc->npages = 0;

    for (int j=0; j<proc->maxpages; j++) {
        proc->pages[j].frame = -1;
        proc->pages[j].block = -1;
        proc->pages[j].on_disk = 0;
    }


    // Limpar frames
    for (int i=0; i<pager.nframes; i++) {
        if (pager.frames[i].pid == pid) {

            pager.frames[i].pid = -1;
            pager.frames[i].page = -1;
            pager.frames[i].dirty = 0;
            pager.frames[i].prot = PROT_NONE;

            pager.frames_free++;
        }
    }

    // Limpar blocos (basta indicar que pode ser usado)
    for (int i=0; i<pager.nblocks; i++) {
        if (pager.block2pid[i] == pid) {

            pager.block2pid[i] = -1;

            pager.blocks_free++;
        }
    }

    pthread_mutex_unlock(&pager.mutex);
}


void* pager_extend(pid_t pid) {
    pthread_mutex_lock(&pager.mutex);

    if (pager.blocks_free == 0) {
        pthread_mutex_unlock(&pager.mutex);
        return NULL;
    }

    // Encontrar o processo correspondente
    struct proc *process = NULL;
    for (int i = 0; i < pager.nblocks; i++) {
        if (pager.pid2proc[i] && pager.pid2proc[i]->pid == pid) {
            process = pager.pid2proc[i];
            break;
        }
    }

    // Processo PID não foi encontrado
    if (process == NULL) {
        pthread_mutex_unlock(&pager.mutex);
        return NULL;
    }

    // Verificar se tem espaço para alocar uma nova página
    if (process->npages + 1 > process->maxpages) {
        pthread_mutex_unlock(&pager.mutex);
        return NULL;
    }

    // Basicamente o bloco deve ser achado, já que tem páginas livres
    int block = -1;
    for (int i = 0; i< pager.nblocks; i++) {
        if (pager.block2pid[i] == -1) {
            block = i;
            break;
        }
    }

    // Não deve cair aqui nunca, mas por precaução
    if (block == -1){
        pthread_mutex_unlock(&pager.mutex);
        return NULL;
    }

    pager.block2pid[block] = process->pid;

    process->pages[process->npages].block = block;

    pager.blocks_free--;

    process->npages++;

    // Calcula endereço do alocamento
    void *vaddr = (void*) UVM_BASEADDR + (process->npages - 1) * sysconf(_SC_PAGESIZE);

    pthread_mutex_unlock(&pager.mutex);

    return vaddr;
}


int pager_release_and_get_frame() {
    while(1) {
        pager.clock = (pager.clock + 1) % pager.nframes;

        struct frame_data *frame = &pager.frames[pager.clock];
        
        // Algoritmo da segunda chance
        if (frame->prot != PROT_NONE) {
            frame->prot = PROT_NONE;
            intptr_t address = UVM_BASEADDR + frame->page * sysconf(_SC_PAGESIZE);
            mmu_chprot(frame->pid, (void*)address, frame->prot);
            continue;
        }

        // Encontrar o processo correspondente
        struct proc *proc = NULL;
        for (int i = 0; i < pager.nblocks; i++) {
            if (pager.pid2proc[i] && pager.pid2proc[i]->pid == frame->pid) {
                proc = pager.pid2proc[i];
                break;
            }
        }

        struct page_data *page = NULL;
        for (int i=0; i < proc->maxpages; i++) {
            if (proc->pages[i].frame == pager.clock) {
                page = (struct page_data*) &proc->pages[i];
            }
        }

        page->frame = -1;
        intptr_t address = UVM_BASEADDR + frame->page * sysconf(_SC_PAGESIZE);
        mmu_nonresident(proc->pid, (void*)address);

        if (frame->dirty == 1) {
            mmu_disk_write(pager.clock, page->block);
            page->on_disk = 1;
        }

        // Limpar quadro
        frame->pid = -1;
        frame->page = -1;
        frame->dirty = 0;
        frame->prot = PROT_NONE;
        pager.frames_free++;

        return pager.clock;
    }
}

void pager_fault(pid_t pid, void *addr) {
    pthread_mutex_lock(&pager.mutex);

    // Encontrar o processo correspondente
    struct proc *process = NULL;
    for (int i = 0; i < pager.nblocks; i++) {
        if (pager.pid2proc[i] && pager.pid2proc[i]->pid == pid) {
            process = pager.pid2proc[i];
            break;
        }
    }

    // Assumindo que o restante do programa está correto, não deve cair aqui
    if (process == NULL) {
        fprintf(stderr, "Não foi possível encontrar o processo\n");
    }

    // Calcular a página
    int page = ((intptr_t)addr - UVM_BASEADDR) / sysconf(_SC_PAGESIZE);

    if (page >= process->npages) {
        fprintf(stderr, "Processo não tem permissão para acessar a página requerida\n");
    }

    if (process->pages[page].frame == -1) {

        int free_frame = -1;

        for (int frame = 0; frame < pager.nframes; frame++) {
            if (pager.frames[frame].pid == -1) {
                free_frame = frame;
                break;
            }
        }

        int frame = pager.frames_free > 0
            ? free_frame
            : pager_release_and_get_frame();

        pager.frames[frame].pid = process->pid;
        pager.frames[frame].page = page;
        pager.frames[frame].prot = PROT_READ;
        pager.frames_free--;

        if (process->pages[page].on_disk) {
            mmu_disk_read(process->pages[page].block, frame);
            process->pages[page].on_disk = 0;
        } else {
            mmu_zero_fill(frame);
        }

        process->pages[page].frame = frame;

        void *vaddr = (void*) UVM_BASEADDR + page * sysconf(_SC_PAGESIZE);
        mmu_resident(process->pid, vaddr, frame, pager.frames[frame].prot);
    }
    
    else {
        int frame = process->pages[page].frame;

        pager.frames[frame].prot |= PROT_WRITE;
        pager.frames[frame].dirty = 1;

        void *vaddr = (void*) UVM_BASEADDR + page * sysconf(_SC_PAGESIZE);

        mmu_chprot(process->pid, vaddr, pager.frames[frame].prot);
    }

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