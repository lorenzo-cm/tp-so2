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
    pager.clock = -1;
    pager.frames = (struct frame_data *) malloc(nframes * sizeof(struct frame_data));
    for (int i = 0; i < nframes; i++) {
        pager.frames[i].pid = -1;
        pager.frames[i].page = -1;
        pager.frames[i].prot = PROT_NONE;
        pager.frames[i].dirty = 0;
    }

    pager.nblocks = nblocks;
    pager.blocks_free = nblocks;
    pager.block2pid = (pid_t *) malloc(nblocks * sizeof(pid_t));
    for (int i = 0; i < nblocks; i++) {
        pager.block2pid[i] = -1;
    }
    
    // Criar vetor com número máximo de processos (um processo para cada bloco)
    // Ficar alocando e desalocando o processo da mt trabalho e tava dando errado
    // Essa abordagem mantem o número de processos fixos e pid -1 no elemnto significa
    // que não tem um processo ativo nesse espaço do vetor 
    pager.pid2proc = (struct proc **) malloc(nblocks * sizeof(struct proc *));
    for (int i = 0; i < pager.nblocks; i++) {
        struct proc *new_proc = (struct proc *) malloc(sizeof(struct proc));

        new_proc->pid = -1;
        new_proc->npages = 0;
        new_proc->maxpages = (UVM_MAXADDR - UVM_BASEADDR + 1) / sysconf(_SC_PAGESIZE);
        new_proc->pages = (struct page_data *) malloc(new_proc->maxpages * sizeof(struct page_data));

        for (int j = 0; j < new_proc->maxpages; j++) {
            new_proc->pages[j].block = -1;      // -1 para indicar que ainda não foi alocado
            new_proc->pages[j].on_disk = 0;
            new_proc->pages[j].frame = -1;      // -1 para indicar que ainda não foi alocado
        }

        pager.pid2proc[i] = new_proc;
    }
}

void pager_create(pid_t pid) {
    pthread_mutex_lock(&pager.mutex);
    
    // Adicionar o novo processo à lista de processos
    // Para isso é necessário procurar por um lugar vago
    for (int i = 0; i < pager.nblocks; i++) {
        // Se o lugar estiver vago
        if (pager.pid2proc[i]->pid == -1) {
            pager.pid2proc[i]->pid = pid;
            break;
        }
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

    // Processo não encontrado, saia da função
    if (proc == NULL) {
        pthread_mutex_unlock(&pager.mutex);
        return; 
    }

    // Resetar/limpar processo
    proc->pid = -1;
    proc->npages = 0;

    for (int i=0; i<proc->maxpages; i++) {
        proc->pages[i].frame = -1;
        proc->pages[i].block = -1;
        proc->pages[i].on_disk = 0;
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
    if (process->npages == process->maxpages) {
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

    // Configurar bloco e atualizar pager
    pager.block2pid[block] = process->pid;

    process->pages[process->npages].block = block;

    pager.blocks_free--;

    process->npages++;

    // Calcula endereço do alocamento
    void *vaddr = (void*) UVM_BASEADDR + (process->npages - 1) * sysconf(_SC_PAGESIZE);

    pthread_mutex_unlock(&pager.mutex);

    return vaddr;
}


int pager_second_chance() {
    while(1) {

        // Em particular, o paginador deve remover as permissões de leitura e escrita
        // ao dar uma segunda chance a uma página, e reatribuir essas permissões 
        // quando o programa realizar o primeiro acesso após a página ter recebido
        // a segunda chance.


        // Próximo elemento no vetor circular
        pager.clock = (pager.clock + 1) % pager.nframes;

        // Tem de ser ponteiro para ser mutável
        struct frame_data *frame = &pager.frames[pager.clock];
        
        // Tira permissão caso tenha
        if (frame->prot != PROT_NONE) {
            frame->prot = PROT_NONE;
            // intptr_t to convert void pointer into int pointer
            intptr_t address = UVM_BASEADDR + frame->page * sysconf(_SC_PAGESIZE);

            // Mudar permissão
            mmu_chprot(frame->pid, (void*)address, frame->prot);
            continue;
        }

        // Encontrou qual frame deve ser jogado para o disco

        // Encontrar o processo correspondente para setar o frame como inacessivel
        struct proc *proc = NULL;
        for (int i = 0; i < pager.nblocks; i++) {
            if (pager.pid2proc[i] && pager.pid2proc[i]->pid == frame->pid) {
                proc = pager.pid2proc[i];
                break;
            }
        }

        // Encontrar o frame com o index do frame a ir para o disco
        struct page_data *page = NULL;
        for (int i=0; i < proc->maxpages; i++) {
            if (proc->pages[i].frame == pager.clock) {
                page = (struct page_data*) &proc->pages[i];
            }
        }

        // Seta o frame como fora da memória
        page->frame = -1;

        // intptr_t to convert void pointer into int pointer
        intptr_t address = UVM_BASEADDR + frame->page * sysconf(_SC_PAGESIZE);

        // Retirar mapeamento
        mmu_nonresident(proc->pid, (void*)address);


        // Se o frame tiver sido mexido, entao escreve ele dnv no bloco
        // E manda ele pro disco (basta setar a flag no pager)
        if (frame->dirty == 1) {
            mmu_disk_write(pager.clock, page->block);
            page->on_disk = 1;
        }

        // Limpar quadro para novo uso
        frame->pid = -1;
        frame->page = -1;
        frame->dirty = 0;
        frame->prot = PROT_NONE;
        pager.frames_free++;

        return pager.clock;
    }
}

void pager_fault(pid_t pid, void *addr) {

    // Funcao nao deve retornar Nada

    pthread_mutex_lock(&pager.mutex);

    // Encontrar o processo correspondente
    struct proc *process = NULL;
    for (int i = 0; i < pager.nblocks; i++) {
        if (pager.pid2proc[i]->pid == pid) {
            process = pager.pid2proc[i];
            break;
        }
    }

    // Assumindo que o restante do programa está correto, não deve cair aqui
    if (process == NULL) {
        return;
    }

    // Calcular o índice da página
    // intptr_t to convert void pointer into int pointer
    int page = ((intptr_t)addr - UVM_BASEADDR) / sysconf(_SC_PAGESIZE);

    // Talvez seja necessário ver se a página é do processo

    // Se a página não estiver alocada em memória
    if (process->pages[page].frame == -1) {


        int frame;

        // Se tem frame disponível, basta encontrá-lo e usar
        if (pager.frames_free > 0) {

            for (int i = 0; i < pager.nframes; i++) {
                if (pager.frames[i].pid == -1) {
                    frame = i;
                    break;
                }
            }

        // Caso contrário é necessário utilizar o algoritmo da segunda chance
        } else {
            frame = pager_second_chance();
        }

        // Agora basta setar o frame (amem)
        pager.frames[frame].pid = process->pid;
        pager.frames[frame].page = page;
        pager.frames[frame].prot = PROT_READ;
        pager.frames_free--;


        // Se tava no disco antes (me buguei mas foi)
        if (process->pages[page].on_disk) {
            mmu_disk_read(process->pages[page].block, frame);
            process->pages[page].on_disk = 0;
        } else {
            mmu_zero_fill(frame);
        }

        process->pages[page].frame = frame;

        void *vaddr = (void*) UVM_BASEADDR + page * sysconf(_SC_PAGESIZE);

        // Alocar o frame
        mmu_resident(process->pid, vaddr, frame, pager.frames[frame].prot);
    }
    
    else {
        // Quando o processo quer escrever

        int frame = process->pages[page].frame;

        // aparentemente é binario e tem que fazer or
        // valorres = 1, 2, 4, 0
        pager.frames[frame].prot |= PROT_WRITE;
        pager.frames[frame].dirty = 1;

        void *vaddr = (void*) UVM_BASEADDR + page * sysconf(_SC_PAGESIZE);

        mmu_chprot(process->pid, vaddr, pager.frames[frame].prot);
    }

    pthread_mutex_unlock(&pager.mutex);
}


int pager_syslog(pid_t pid, void *addr, size_t len) {
    pthread_mutex_lock(&pager.mutex);
  
    struct proc *proc = NULL;
        for (int i = 0; i < pager.nblocks; i++) {
            if (pager.pid2proc[i] && pager.pid2proc[i]->pid == pid) {
                proc = pager.pid2proc[i];
                break;
            }
        }

  if (proc == NULL) {
    exit(EXIT_FAILURE);
  }

  char* buf = (char*) malloc((len + 1) * sizeof(char));

  if (buf == NULL) {
    exit(EXIT_FAILURE);
  }

  for (int i=0; i<len; i++) {
    // intptr_t to convert void pointer into int pointer
    int page = ((intptr_t)addr + i - UVM_BASEADDR) / sysconf(_SC_PAGESIZE);

    if (page >= proc->npages || proc->pages[page].frame == -1) {
      pthread_mutex_unlock(&pager.mutex);
      return -1;
    }

    buf[i] = (char)pmem[proc->pages[page].frame + i];
  }

  for(int i = 0; i < len; i++) {
    printf("%02x", (unsigned)buf[i]);
    if (i == len - 1) printf("\n");
  }

  free(buf);

  pthread_mutex_unlock(&pager.mutex);
  return 0;
}